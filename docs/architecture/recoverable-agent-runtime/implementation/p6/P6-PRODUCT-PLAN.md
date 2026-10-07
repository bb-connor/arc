# Recovery P6 Product and Qualification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking. Implementation is inline; one fresh final reviewer follows all tasks.

**Goal:** Deliver protected guided setup, classified policy feedback and separately signed maintenance, thin LangGraph/CrewAI integration, and reproducible matched utility and overload qualification.

**Architecture:** The existing Rust kernel, process journal and fenced SQLite authority continue to own every decision and effect. Product services add bounded projections and guarded operator flows around those owners. Host adapters transport stable commands; a qualification harness uses actual native stores/endpoints and actual framework/provider execution.

**Tech Stack:** Rust 1.94.1, edition 2021; existing no-std/alloc contracts with Rust 1.93 compatibility; Axum/Tokio; canonical JSON and Ed25519; SQLite; generated Rust/Python/TypeScript; pinned LangGraph and CrewAI; pinned OpenAI model.

**Spec:** `08-protocol-operations.md`, `09-conformance.md`, `01-security-model.md` and `10-delivery-decisions.md` in the architecture directory. The requirement crosswalk covers SEC-12, OPS-04, OPS-07, OPS-09, TEST-05, TEST-06, TEST-07 and TEST-08.

## Global Constraints

- P5 native Linux acceptance is mandatory; seal its final source and artifact snapshot before modifying P6 runtime sources. Preserve all predecessor seals.
- Rust owns authority, effect semantics, label arithmetic and native replay. No second SDK retry coordinator, generic force retry or complaint-derived grant.
- Canonical closed versioned DTOs, bounded collections/text/verification, distinct signature domains, redacted Debug and fail-closed errors.
- A protected setup report requires actual model-free benign, denied and fresh-writer restart evidence. Parsed configuration is insufficient.
- Maintenance proposals are classified untrusted input. Only the currently selected independent operator key can authorize a fresh base-bound deployment change.
- No native transaction or process-journal lock spans provider, framework, model, sink or arbitrary callback I/O.
- A dedicated bounded settlement executor remains available under intake saturation. No unbounded waiting queue.
- No new unsafe implementation, lint allowance, em dash, or shared dirty checkout reset. Use conventional commits only if they can include exclusively this phase; otherwise retain an exact phase delta archive.
- Only measured supported features are enabled. P5 remains the model-disabled Boolean profile; this phase does not expand its cage channels or qualify covert channels.
- Declare the corpus, hosts, model/version, task policy, budgets, faults, denominators and thresholds before live comparative results. Retain every trial, including errors.
- Local, native Linux, live framework/model, hosted CI and deployment evidence are separate claims.

## Review Focus

1. A replayed policy complaint or signed old proposal must not reapply a deployment, expose attachments to a weaker audience or clear retained uncertainty. Task 2 tests exact replay, stale base, foreign signer and revoked reader.
2. A setup token from a different store, scope, policy or serving generation must not unlock protected work. Task 3 tests each substitution, missing mediator and a failed benign counterpart.
3. An HTTP disconnect must not release capacity while its already captured native task still owns work. Task 4 tests actual held provider work, dropped callers and recovery after restart.
4. A framework model that declines to call its tool or exceeds budget must count as an unsuccessful trial, not be repaired silently by the harness. Task 5 tests skipped tool, extra model call, parser error and denominator preservation.
5. Historic abstract model results must not be presented as current SQL, provider or complete-system proof. Task 5 recomputes source hashes and explicitly maps assumptions and uncovered seams.

## File Responsibilities

Portable product DTOs live in `chio-security-types/src/recovery/product.rs`; signatures in `chio-core-types/src/recovery/product.rs`; authoritative schemas and vectors in the existing wire system. Native policy report/maintenance storage lives beside `admission_operation_store/recovery` and `semantic`; guided setup beside control-plane recovery. Reserved executor code stays in recovery transport. CLI and SDK clients remain thin. Framework adapters belong to their existing SDK packages. Qualification fixtures and reporting live in `fixtures/recovery-product/` and phase evidence, with no production dependency on evaluation packages.

### Task 1: Bounded product contracts and signatures

**Files:** Create portable/core `recovery/product.rs`, owning contract tests, authoritative product schemas and vectors; modify only their exports, domain inventory, registry and generated bindings.

**Interfaces:** Produce `DecisionReportV1`, `PolicyMaintenanceProposalV1`, `PolicyDeploymentChangeV1`, `RecoverySetupProbeV1`, `RecoverySetupReportV1`, their `validate()` methods, and separately framed `SignedPolicyDeploymentChangeV1`, `SignedRecoverySetupProbeV1`, `SignedRecoverySetupReportV1`. Use existing RecoveryScopeV1, safe integers, typed digests, ArtifactVersionRefV1, bounded text and lists. Each signed type exposes the existing body/signing_bytes/authority_key/verify_signature API.

- [x] Write contracts tests for 4096-byte reporter text, 1024-byte desired outcome, at most eight classified artifact references, base/target/proposal substitution, unsafe integer, duplicate field and Debug canaries. Proposal must include rationale (4096), affected contracts (16), benign/adversarial trajectory references (16 each), expected effects and rollback policy/plan. Setup claims contain actual retained native identities and distinct previous/current serving fences.

```rust
assert!(decode_contract::<DecisionReportV1>(&oversized_text).is_err());
assert!(!format!("{report:?}").contains("feedback-secret-canary"));
assert_ne!(change.signing_bytes()?,
           setup.signing_bytes()?);
```

- [x] Run `cargo test --offline --locked -p chio-core-types --test recovery_p6_contracts`.
  Expected: FAIL because the product contract/API does not yet exist.
- [x] Implement focused DTO validation and reuse `signed_authority!` with independent versioned domains. Keep fields closed and all required bindings non-null; reject empty trajectory coverage and identical base/target policy.
- [x] Add authoritative schemas and positive/negative vectors, regenerate all three languages and the complete registry/manifest.
- [x] Run the contract test, vector recomputation, generator checks, alloc/std/WASM and Rust 1.93 portable checks.
  Expected: every positive accepts and every intended mutation refuses, with generated bytes current.
- [x] Record the exact delta and commands in the task ledger. Preserve predecessor files as historical artifacts.

### Task 2: Classified reports and separately authorized policy maintenance

**Files:** Create control-plane `recovery/maintenance.rs`, native recovery report storage, owning native tests; refactor semantic installation into a reusable transaction helper without weakening existing compilation/root checks; expose new typed SDK/HTTP report and maintenance projections.

**Interfaces:** Consume Task 1 contracts. Produce `RecoveryMaintenanceRuntime::submit_report(capability, command_id, report)`, `read_report(capability, report_id)`, `propose(capability, proposal)` and native `apply_reviewed_semantic_deployment(change, installation)`. The existing trusted semantic installation is the actual target. Base/target policy digests identify the canonical selected publisher roots, package digests and routes; deployment digests identify its complete signed deployment body, including generation and native context. Generation-only changes do not masquerade as a policy fix. This route changes the actual compiled semantic policy, not a label on an unchanged native guard. Native guard engine reload remains a separate operator restart/configuration path and is not claimed by this endpoint. Add one explicit Maintain permission within the existing maximum 16 permission list.

- [x] Write native tests using actual SqliteAuthorityStore, native restricted source and immutable artifact metadata. Assert report text/attachment labels survive restart, exact replay creates one record, changed semantic content conflicts, lower clearance/refused capability returns no canary, and report submission creates no provider effect or policy mutation. Reports may describe refused/pending decisions; they do not require a completed effect.
- [x] Run `cargo test --offline --locked -p chio-control-plane --lib p6_policy_ -- --test-threads=1`.
  Expected: FAIL on missing maintenance API.
- [x] Authenticate Report/Inspect/Maintain with the existing kernel actor path; freshly verify the actor in the fenced SQLite transaction. Join current source, workflow and all attachment confidentiality/influence; keep only immutable references. Aggregate report quotas across a tenant/domain, preserve replay identity and reserve settlement headroom.
- [x] Add native tests proving reporter/blocked-agent and maintenance-capability signatures cannot deploy; selected operator signature can apply a reviewed benign change; stale base, wrong target, missing trajectory, old serving fence and old rollback signature refuse. Check the actual compiled route/deployment changed, pending bases stale and previously completed original effects remain owned.
- [x] Implement operator change verification against the current stored operator root and exact stored proposal/base. Compile the entire target installation before the owning atomic write; recheck current base, report/proposal identity, native binding and generation inside that transaction. Store application identity with deployment so exact lost-ack replay cannot reapply it. Rollback is a new signed generation and proposal.
- [x] Run the new native tests and all P1/P3/P4/P5 owning regression suites.
  Expected: benign target succeeds; every negative leaves policy, effect count, original operation and replay consumption unchanged.
- [x] Record delta and test evidence.

### Task 3: Protected guided setup and CLI

**Files:** Create control-plane `recovery/setup.rs` and setup transport; extend thin CLI/client surfaces; add actual restart tests and generated contract tests.

**Interfaces:** Consume signed setup DTOs. Produce `RecoverySetupService::probe(capability, workflow_id)` and `qualify(capability, signed_probe)`, plus `protected_recovery_router(service)`. Probe reads the actual completed native operation/receipt, checks the selected closure/credentials and performs a real refused command. Qualify requires a fresh native writer fence, reopens retained custody, recovers the identical operation/result and signs the report. Constructor/profile checks and current authority remain mandatory.

- [x] Write native tests: current same-writer qualification refuses; actual writer reopen succeeds with the same native effect and tree charge; tampered/foreign policy/store/scope probes refuse; missing required mediator refuses visibly; qualified report from an earlier deployment cannot unlock new work. Gate requests before readiness and after a profile change.

```rust
assert!(service.qualify(&control, &probe).is_err());
let reopened = reopen_real_native_writer(&directory)?;
let report = reopened.setup.qualify(&control, &probe)?;
assert_eq!(independent_effect_count(&directory)?, 1);
assert_eq!(report.authority_key(), &operator);
assert!(report.verify_signature()?);
```

The harness helpers construct actual owning stores and count their endpoint rows; no boolean callback can declare a self-test successful.

- [x] Run `cargo test --offline --locked -p chio-control-plane --lib p6_setup_ -- --test-threads=1`.
  Expected: FAIL on absent setup service.
- [x] Implement signed custody based on current native records and actual fences, with strict bounded one-probe/replay semantics. A report is authenticated evidence, not a new grant. Fresh actor/profile checks gate all protected routes even after readiness. Persist readiness in the same native authority and compare its deployment/fence inside owning new-work mutations and capture. Only the operator-pinned exact self-test workflow may run before readiness; inspect, cancellation and historical settlement remain available. A profile reload invalidates readiness atomically, including when it races HTTP preflight.
- [x] Add `chio recovery setup probe` and `qualify` over the shared HTTP protocol with bounded files/credentials and no retries or redirects. Present required operator restart and typed readiness/uncovered-path results.
- [x] Run native tests and CLI transport tests; exercise the actual CLI against the qualification host. Retain benign/refused/restart evidence and installation step counts.
  Expected: no protected work is accepted from configuration parsing alone; all successful reports bind the exact installed/source profile.
- [x] Record delta and test evidence.

### Task 4: Reserved settlement and real host adapters

**Files:** Create bounded recovery settlement executor and owning overload tests; modify transport to reserve before submission; create thin LangGraph and CrewAI recovery adapters/tests in their existing SDK packages; add native qualification endpoint fixture.

**Interfaces:** Consume existing RecoveryRuntime execute/review/settle and Task 2/3 product protocol. Produce a two-worker bounded settlement executor independent of Tokio intake blocking workers; recovery adapters preserve stable Rust-produced command IDs and opaque canonical bytes, exposing only typed outcomes. No fallback tool execution.

- [x] Write actual native HTTP overload test with Tokio max_blocking_threads=4. Hold four provider calls in four real native scopes after capture, flood intake, drop callers, and settle an already owned fifth operation. Assert settlement completes within the predeclared two-second deadline, exactly one existing effect remains, excess intake returns a bounded generic response and no implicit new attempt appears after restart.
- [x] Run the overload test on the existing shared blocking executor.
  Expected: the settlement deadline fails for actual intake starvation.
- [x] Implement two dedicated owned settlement workers, maximum two outstanding jobs and fail-closed startup/try-submit behavior. Retain permits until native work completes after disconnect; no unbounded send/wait queue or new retry authority. Bound planning/review/approval/report paths separately from settlement under the operator-selected scope.
- [x] Run overload, shutdown/disconnect, panic/refusal and all owning native transport tests.
  Expected: fixed bounds, completed recovery and exact effect ownership under the flood.
- [x] Write adapter tests with actual LangGraph StateGraph and CrewAI BaseTool/Crew. Have each carry a canonical Rust command unchanged to the native listener; verify no fallback after unavailable/refused response, stable replay, bounded model/tool steps and no credential/raw error leakage.
- [x] Implement thin adapters over the generated RecoveryClient. Both hosts have the same selected origin/authority and explicit task-owned command identity. The adapter does not approve its own complaint or recompute labels. Return only bounded decision categories and opaque retained references to framework checkpoints; protected raw original responses stay behind fresh Rust read authority. Disable CrewAI tool/result caching, and reauthorize LangGraph replay through Rust instead of trusting a cached response. Test revoked replay and protected canaries in actual saved state.
- [x] Run pinned package tests and actual host-to-Rust benign/refused/replay integration.
  Expected: identical native command/effect identity and independently counted useful effect in each host, zero effect on refusal.
- [x] Record delta and test evidence.

### Task 5: Matched live campaign, performance, assurance and final qualification

**Files:** Create `fixtures/recovery-product/` qualification fixture/harness and predeclared manifest; phase source/profile maps, supported matrix, metrics/reproducer, coverage and sealing auditor. Preserve immutable P5 snapshot/archive.

**Interfaces:** Consume all Task 1-4 contracts and actual host adapters. Produce auditable native/host/provider results with every denominator/error retained, separate safety and utility, assumptions/limitations and current source/profile hashes.

- [x] Before live data collection, seal a manifest with exact host/package/model versions, public synthetic tasks, tool/provider policy, fault corpus, 96 trials (two hosts, two workflows, two arms, four cases per workflow, three repetitions), at most four model calls and eight tool actions per trial, bounded prompts/output/attempt time, no hidden retries. Use exact `gpt-5.4-mini-2026-03-17`; resolve host versions from their installed pinned distributions. The competent baseline has stable operation IDs, idempotency, authoritative outcome lookup and normal ACLs. Compare OpenAPPA only on supported common semantics; unsupported rows are explicit.
- [x] Use support-to-public-issue and protected artifact reuse/restart as the two workflows. Four predeclared cases each cover useful authorized work, lost acknowledgement/restart, wrong audience/authority and conflicting replay or stale basis. Each arm receives the same tasks, actor rights, resource behavior and budget. Neither model sees real credentials or private user data. Framework refusal or skipped tools counts as an actual trial outcome.
- [x] Test the reporting harness with a deliberate missing trial, duplicate identity, mismatched authority/model, hidden retry, unsupported case, skipped tool and error row.
  Expected: invalid/missing denominators reject; genuine failure remains in summaries.
- [x] Implement the actual Rust native fixture and competent baseline endpoint, framework/model runners and source-bound reporter. Compute per-stratum sample counts, completion/recovery/violation rates with Wilson intervals, latency/token distributions and unresolved ages. Count native effects/charges/labels independently. Measure actual adapter code and installation actions rather than inventing savings.
- [x] Run the 96 predeclared actual trials. Retain all attempts, token usage, returned model ID and endpoint evidence. A model/provider failure does not authorize silently changing the declared task set/model or censoring errors.
- [x] Run quiet same-hardware/toolchain/profile P0 pure and native baseline commands. Enforce the retained native p95 ceiling 220683049 ns and existing pure ceilings; preserve actual samples and denominator. Run native overload/resource checks independently from model/human latency.
- [x] Recompute parser/concurrency/model source hashes and map each finite modeled transition and assumption to its actual owning function and cutpoint test. Declare uncovered provider/storage/full-system proofs explicitly. Re-run applicable model mutations, parser corpus, native concurrency and crash campaign.
- [x] Run complete current phase gates: formatting, clippy -D warnings, owning/native/store suites, schemas/domains/layering/hygiene, generated cross-language vectors, no-std/WASM/MSRV, actual Linux and package integrity. Freeze a current reviewed source delta and request one fresh whole-phase review on the most capable available model.
- [x] Re-grade findings by user impact. One test-first fix pass resolves every P0/P1/Important finding; defer only identified Minor findings with an exhaustive ledger. Re-run affected full gates, seal and independently audit source/profile/evidence/coverage and prior immutable artifacts.
- [x] Mark P6 accomplished only when its eight obligations and required numeric budgets pass. State exact supported matrix, remaining unsupported cases, review scope and hosted/deployment limits. The roadmap has no invented P7; identify the next actual operational/release work from retained delivery decisions.

## Self-review and execution authorization

All eight P6 obligations map to the five tasks: OPS-07 Task 2; OPS-04 Task 3; OPS-09 Task 4; SEC-12 and TEST-05 through TEST-08 Task 5, consuming native evidence from earlier tasks. Closed DTOs and generated bindings support every task. The five review focus conditions have owning negative and benign tests. The user repeatedly authorized execution of P5 then P6 and delegated OCI/provider/host choice; continue inline without another plan approval prompt. Existing dirty predecessor work is preserved and task deltas are recorded independently of HEAD.

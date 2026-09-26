# Security Roadmap Assurance Closeout Plan

> **For agentic workers:** Use superpowers:executing-plans. Preserve the existing single-agent execution instruction and one Cargo owner per checkout. Complete each implementation packet with its owning regressions before starting the next.

**Goal:** Finish the remaining security implementation and qualify one supported developer-preview candidate with explicit evidence for authorization, confinement, recovery and truthful receipts.

**Architecture:** Continue the existing kernel, broker, cage, durable stores and response authority. Finish the signed M7 dry-run composition, sharing production validation and pure transition rules while separating simulation evidence from live effect authority. Refactor touched modules around authority and resource ownership; retain existing tooling and acceptance inventories.

**Tech Stack:** Rust, SQLite, Tokio, existing proptest/Loom/libFuzzer infrastructure, Kani, Lean and TLA+/Apalache, supported Linux x86_64 native enforcement and GitHub Actions.

**Spec:** [Roadmap completion plan](2026-09-22-security-roadmap-completion.md), [launch execution contract](../../security/launch-execution-plan.md), [active-defense rollout](../../security/active-defense-rollout.md), and [review remediation](../../reviews/2026-09-25-security-roadmap-remediation.md). This is a sequencing and assurance addendum. It preserves every requirement in the original plan.

**Extended by:** the [engineering excellence addendum](2026-09-26-security-engineering-excellence.md), which adds Packet 0 (build, gate and measurement integrity) before Packet 1, corrections 1A to 1E inside Packet 1, corrections 2A, 2B, 3A, 4A and 4B with their parent packets, and Packets 7 (structural remediation), 8 (accounting type safety), 9 (measurement and hot-path cost) and 10 (state recovery and isolation boundaries) after Packet 6. Its findings are in code quality review [pass 1](../../reviews/2026-09-26-security-code-quality-review.md) (Q series), [pass 2](../../reviews/2026-09-26-security-code-quality-review-pass-2.md) (R series), [performance pass 3](../../reviews/2026-09-26-security-performance-review-pass-3.md) (P series) [pass 4](../../reviews/2026-09-26-security-review-pass-4.md) (S series), the [unrepresentable-defects design](../specs/2026-09-26-unrepresentable-defects-design.md) (pass 5) and the [pass 6](../../reviews/2026-09-26-review-validation-pass-6.md) and [pass 7](../../reviews/2026-09-26-review-validation-pass-7.md) validations; its standing rules are the [security engineering standard](../../security/engineering-standard.md). Read the revised execution order there before starting a packet.

**Read correction 1D first.** Packet 1's exit requires negative tests that distinguish missing approval, expired approval, stale scope, overlap, both expiry orders, rollback conflict and cross-mode replay. All of those currently reject with the single value `StateMachineError::InvalidDispatch`, so that corpus cannot demonstrate what it claims until rejection provenance is restored. Writing it first means rewriting it.

## Global constraints

- Fail closed. Invalid configuration rejects at load. Signed payloads use canonical JSON and explicit schema versions.
- Preserve single-operator preview scope and automatic-response-disabled defaults. Permanent revocation remains manual.
- Unknown effect outcomes remain unknown until exact durable readback resolves them. Retry never creates new authority.
- Use `umask 022`, locked dependencies, `CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1` and `CHIO_CHECKOUT_ROOT` for an external Cargo target. Preserve assertions, deadlines and original failed-run evidence.
- Linux native acceptance uses the designated x86_64 profile, kernel 6.7 or newer and the required confinement prerequisites. Portable tests and a GNU static PIE probe run do not qualify the designated musl package.
- Keep `output/` and historical evidence intact. No broad source restructuring during a qualification run.
- Direct self-review is not independent reviewer evidence. Publication and operational promotion retain their existing authority boundaries.
- No em dashes. Use conventional commits. No production `unwrap` or `expect`.

## Verified starting point

Research snapshot: September 25 local time / September 26 UTC, source `3cd73631a18a6ec169b1e1a5bbd3ebe8bcb00130` on draft [PR #1160](https://github.com/bb-connor/arc/pull/1160).

- The remediation report records implemented fixes and completed focused tests. It explicitly excludes full final-source qualification and privileged enforced CLI discovery end to end.
- [Current-source CI](https://github.com/bb-connor/arc/actions/runs/36213772652) has unfinished jobs. Its [Cargo Vet job](https://github.com/bb-connor/arc/actions/runs/36213772652/job/108326280292) terminated with `aws-lc-rs:1.18.1 missing ["safe-to-deploy"]`. The raw job log is retained at `/tmp/chio-security-review-24b995/cargo-vet-3cd73631a1-hosted.log`.
- Trusted-definition PR #1167 and prerequisite PR #1168 remain open. The configured App key is only one input to the unfinished trusted-capture chain.
- The qualification ledger records prior-source passes for all 35 M7 campaigns, both million-entry M8 campaigns, M9 native installation, 49 PR-tier Kani proofs and all 30 original fuzz campaigns. Preserve those results; do not label them qualification of this later source.
- [Retention liveness issue #1045](https://github.com/bb-connor/arc/issues/1045) remains open. The original property is still quarantined. The legacy temporal command also lacks a terminal passing result at its original bound.

## Review focus

1. Valid signed simulation material must never be accepted as live dispatch authority, including after restart or configuration changes. Packet 1 owns mode substitution and cross-mode replay tests.
2. Expiry, cancellation, disabled credentials and emergency stop can race commitment. Packet 2 owns deterministic before/after-commit races and externally observed effects.
3. A process can die after durable state changes but before acknowledgement. Packet 2 owns actual process death, acknowledgement loss and exact restart reconciliation.
4. Overlapping restrictions, reordered TTLs and rollback conflicts must preserve unrelated contributions. Packets 1 and 4 own generated schedules and bounded transition invariants.
5. Storage pressure, archive replacement and blocked synchronization must preserve evidence and produce bounded failure. Packets 2 and 3 own real-store fault tests and the retention liveness repair.

## Execution order

Start packet 1 as the next product-code change. Advance packet 5's audit and trusted-delivery work while remote gates run, without competing local builds or mutations of frozen inputs. Then complete packets 2-4 and converge on packet 6. A reproduced P0/P1 or failing security invariant takes priority over this order.

Foundation integration retains the original steps 1-4 acceptance boundary. Once those gates close, integrate that candidate and continue later milestones as bounded follow-up changes. The new assurance work below does not silently make every M7-M11 deliverable a prerequisite for merging the foundation. If source is frozen for capture, use the established isolated-candidate workflow for further implementation.

### Packet 1: Complete the production signed response dry-run

**Owners:** `chio-security-types/src/response.rs`, `chio-quarantine/src/{approval.rs,state_machine.rs,executor.rs}`, `chio-active-response-authority/src/config.rs`, `chio-control-plane/src/security/{active_response.rs,active_response_authority.rs,event_consumer.rs}`, the broker runtime composition, and `chio-core-types/src/receipt/security.rs`.

**Contract:** The rollout requires real approval, capability, causal-scope, receipt and rollback checks without external effects. `SecretBrokerDeploymentBinding.stage` is not this execution-mode contract.

- [ ] Bind an explicit response execution mode into authenticated deployment configuration and signed authorization/evidence. Update affected closed schema versions and readers together. Reject unknown modes and mode substitution; legacy records cannot acquire live authority through inferred defaults.
- [ ] Share the existing plan/approval validators and pure transition rules. Keep the existing `ResponseApprovalCoordinator` boundary: quarantine does not become a second cryptographic approval verifier.
- [ ] Evaluate apply, overlap, expiry and rollback against an immutable, version-bound snapshot using an isolated simulation state. The simulator must not own a live `EffectPort` or external alert-delivery capability. Reuse pure effect-composition rules instead of cloning their policy into a parallel engine.
- [ ] Emit a distinct signed simulation report binding tenant, plan, configuration, authorization, snapshot versions and simulated outcomes. Persist the report through the real receipt path. Simulation never emits live `Applied` evidence, installs an overlay or populates recoverable live dispatch work.
- [ ] Wire the real authority, kernel approval, scheduler/host lifecycle and receipt store through this profile. Preserve the existing live executor's behavior and admission requirements.
- [ ] Add `response_dry_run.rs` owning tests in `chio-quarantine/tests/` and `chio-control-plane/tests/`. Cover all six effect kinds, both approval requirements, missing/expired approval, stale scope, overlap, both expiry orders, rollback conflict, receipt failure, restart and cross-mode replay. Assert zero live effect calls and unchanged live contributions, including denial and failure paths.
- [ ] Run both new test targets plus the affected existing response recovery gate. Commit the behavior and its regressions as one reviewable packet.

**Exit:** A production-composed signed dry-run can be independently verified, models rollback truthfully and cannot authorize or perform a live effect. Simulation success does not establish that a future external effect will succeed.

### Packet 2: Prove the repaired boundaries in real composition

**Owners:** CLI `src/cli/provision/discovery/`, `chio-keyring/tests/independent_services.rs`, `chio-secret-broker/src/process_boundary_tests/`, `chio-control-plane` startup/recovery tests, and `chio-store-sqlite/tests/security_release_recovery/`.

- [ ] Add an enforced privileged discovery integration case on the supported x86_64 runner. Exercise signed manifest admission, selected UID/GID, actual cage restrictions, one absolute timeout, descendant cleanup and host filesystem protection. Keep the existing unconfined demo test separately identified.
- [ ] Exercise keyring startup through the public runtime entry point, including loss of an auditor or receipt sink after activation. Seed installation/readiness must wait for verified completion; restart must recover the same rotation.
- [ ] Extend the existing process-cutpoint harness for the recently changed broker and storage boundaries. Kill the owned process before/after durable commitment, after an effect before acknowledgement, and during recovery. Verify exact replay, no new authority, no duplicate commitment and truthful unknown outcomes.
- [ ] Use deterministic barriers for disable/delete versus dispatch, final-deadline expiry, emergency stop versus replay, and archive authentication versus replacement. Cover SQLite busy/full/write failure where those operations own durability; avoid wall-clock sleeps as synchronization.
- [ ] Use the existing bounded Loom infrastructure only for synchronization logic that can share the actual production decision code. SQLite and OS process assertions remain real integration tests.
- [ ] Run the affected owning targets and native profile, retain original failures and reruns, and commit only actual fixes plus their meaningful regressions.

**Exit:** The repaired behavior holds across public composition and process boundaries. Every crash case states the last durable commit, possible external effect and permitted recovery action.

### Packet 3: Close retention liveness and recovery

**Owners:** `chio-store-sqlite/src/receipt_store.rs`, `receipt_store/tests/{retention.rs,retention_liveness.rs}`, writer/rotation ownership code, and existing scale gates.

- [ ] Reproduce #1045 using its original workload under declared slow-sync/contention conditions. Capture blocked stacks and writer/rotation ownership at the stall. A passing diagnostic is not a root-cause finding.
- [ ] Convert the observed ordering defect into a deterministic Rust regression, fix its owner and execute the unchanged original property. Remove its quarantine only when the failure condition is accounted for and its ordinary CI invocation runs it.
- [ ] Verify that schema-v5 logical evidence identities survive retention, archive reopen, restart and migrations while corrupt or missing payloads fail closed. Include same-inode mutation and path replacement.
- [ ] Repeat the original million-entry append and history-recovery gates once the owning source is stable. Preserve original inventories and measure hot-path/restart cost, memory and disk use against the retained baseline.

**Exit:** The original liveness issue has an evidence-backed disposition, the property executes in its intended lane, and current-source retention/recovery preserves the original signed evidence. A timeout remains incomplete evidence.

### Packet 4: Add targeted stateful fuzzing and model linkage

**Owners:** `fuzz/Cargo.toml`, `fuzz/fuzz_targets/`, production fuzz entry points, `formal/proof-manifest.toml`, `formal/rust-verification/`, `formal/apalache/`, and the existing trace-validation surface.

- [ ] Add two focused harnesses: `response_authority_protocol` for bounded authenticated-envelope decoding/validation, and `response_lifecycle` for generated plan/apply/expire/rollback/restart sequences. Use actual production validation and transition functions. Seed with valid signed fixtures and valid plans so campaigns reach meaningful states; mutate binding fields and ordering as well as raw bytes.
- [ ] Assert semantic oracles: a malformed/rebound envelope grants no authority; dry-run never enters live execution; partial rollback cannot report a clean lift; removing one contribution preserves overlapping restrictions. Minimize every finding into a Rust regression and retained corpus seed.
- [ ] Run time-bounded sanitizer campaigns with the existing pinned toolchains and resource budgets. Record target, source, duration, corpus and crash artifacts. Include new targets in existing inventory/CI selection; a successful build is not a campaign.
- [ ] Extend bounded Kani checks for production pure authorization/transition helpers introduced or changed by these packets. Keep overflow and unwinding assertions enabled; record domain bounds. Preserve existing Lean algebra and canonicalization obligations when their code changes.
- [ ] Add a response lifecycle model covering overlapping actions, owner loss, partial acknowledgement, expiry and rollback. Validate corresponding production traces at the actual commit/effect/receipt boundaries. Require positive exploration plus caught negative mutations for dry-run isolation, no false clean rollback and truthful receipt state.
- [ ] Resolve the existing temporal timeout in its owning lane with an explained model/state-space or implementation repair. Preserve the original failure and invariant. Distinguish bounded safety from liveness assumptions and do not equate model proofs or mirror hashes with full Rust verification.

**Exit:** New campaigns explore the changed trust boundaries and model claims identify production linkage, bounds and remaining assumptions. All existing final acceptance inventories remain required.

### Packet 5: Remove the delivery blockers

**Owners:** `supply-chain/`, the tracked AWS-LC fork and audit evidence, PRs #1167/#1168, protected capture workflows, `chio-enterprise-evidence` provenance, and existing release packaging.

- [ ] Complete the genuine `aws-lc-rs 1.18.1` registry-source audit and independent review of the fork delta. Record an audit only after the exact source, selected features, unsafe boundaries and repaired behavior have been reviewed. No exemption or unsupported certification.
- [ ] Finish reviewed trusted definitions on main and immutable definition/caller rotation. Bind the authorized candidate source, published image manifest digest and independently published verifier source/build/artifact provenance.
- [ ] Execute and independently verify the signed committed capture, including M5 nonce/log joins and required substitution denials. Activate the App-bound required check through the existing authorized procedure.
- [ ] Carry source/package fixes into the actual publishable dependency closure. Rebuild and install the designated native package on a clean host, exercising allow, deny, receipt verification, service death and recovery. Preserve the original handoff's consumer/host requirements.

**Exit:** Dependency policy and the trusted evidence chain pass on the actual candidate; package consumers receive the reviewed implementation without workspace-only patches.

### Packet 6: Freeze, qualify, review and deliver

- [ ] Freeze source, lockfile, schemas, binaries, helper, worker image, verifier and workflow definitions after implementation. Run the original full workspace, strict Clippy, formatting, codegen, consumer, native, formal, fuzz, mutation, scale and release gates on that candidate.
- [ ] Re-run the full 35-campaign M7 gate with all required repository inputs fixed. Preserve existing assertions and failed/retry artifacts. Reuse historical evidence only for explicitly unchanged inputs allowed by the gate contract.
- [ ] Obtain independent final review of the authority, concurrency, recovery and release changes. Resolve all P0/P1 findings and give every remaining finding an explicit disposition.
- [ ] Reconcile terminal hosted attempts, source/PR/remote SHA, review threads, reviewer decisions, capture identity and enforced required checks before integration. Finish original M9/M10 consumer delivery and publish verification through the existing mechanism.
- [ ] Prepare M11 cohort observation and rollback collection. Execute the separately authorized pilot under the original observation and precision thresholds. Insufficient findings keep automatic response in dry-run; calendar evidence is not manufactured from synthetic tests.

## Code review acceptance standard

- Each module owns a coherent resource or decision: authorization, pure transition, durable journal, effect I/O or signed evidence. Replace touched numbered/textual includes with real private module boundaries where that reduces shared scope; do not split files merely to satisfy a line count.
- Keep authority types opaque after verification, bounds explicit and legal transitions exhaustive. Use newtypes or typestate when they prevent a demonstrated invalid state. Introduce traits at real dependency boundaries.
- Resource cleanup uses ownership/RAII. Locks and database transactions cover the commitment they protect and do not accidentally span external I/O. Cancellation has an explicit durable outcome.
- Share security decisions across live, recovery and simulation paths. Avoid duplicate policy implementations, permissive trait defaults, boolean mode flags and generic frameworks without a concrete caller.
- A regression fails for the defect it names. Integration tests observe durable state or actual effects. Fuzzing reaches valid deep states. Formal claims include assumptions and implementation linkage. Test counts and line coverage do not establish threat closure.
- Run focused checks while implementing, then the complete required qualification at the stable candidate. Reuse existing harnesses; create additional tooling only when an uncovered boundary requires it.

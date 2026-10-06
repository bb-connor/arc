# Production readiness review repair plan

> **For agentic workers:** Use Superpowers systematic debugging, TDD and verification before completion. Execute the dependency order below. The user authorizes bounded 6.1 Sol max subagents; keep source ownership disjoint and serialize commits and integration checks.

**Goal:** Repair confirmed remaining P0, P1 and P2 defects in the process/security candidate, reconcile historical review obligations against current source, and obtain genuine final qualification before declaring production readiness.

**Architecture:** Preserve the current capability, receipt and trusted execution contracts. Repair the owning resource or error boundary, reuse existing authenticated readers and ingress reservations, and move one resource reservation through every retention stage. Keep stored-report consistency distinct from externally authenticated history completeness. Freeze the complete source and documentation before regenerating evidence.

**Tech Stack:** Rust 1.95, Cargo, SQLite, duplicate-aware JSON, existing authority clocks, isolated Linux x86_64 qualification and protected GitHub Actions definitions.

**Spec:** `docs/security/landing-ledger.md`, `docs/security/foundation-acceptance-scope.md`, the October 1 execution reviews, and `docs/superpowers/plans/2026-10-05-foundation-ci-feedback.md`.

## Global constraints

- Preserve the original 1609 requirement identities and all failed, cancelled, ignored and unavailable evidence.
- No new optional feature or unrelated research scope. Confirm actual source defects before implementing historical findings.
- Fail closed on invalid input, exhausted capacity, unavailable authority or inconsistent stored evidence.
- Signed JSON remains strict. Unsigned protocol envelopes retain original-byte bounds and duplicate rejection while accepting ordinary JSON numbers.
- Keep both histories, published branches and archives. The active landing queue has at most two PRs.
- Do not weaken a test, audit, resource limit, isolation rule, source binding, trusted workflow, check or protected merge rule.
- Shared diagnostic builds are permitted; final isolated evidence remains cold and source-bound.
- Finish source, status documents and review corrections before evidence refresh. No late documentation edit may invalidate an accepted input binding.

## Review focus

- A notification moved from HTTP through channels into a deferred queue still consumes the same aggregate reservation.
- Unrelated client traffic cannot reset a nested reply deadline, and full ordinary ingress cannot indefinitely block its matching reply or cancellation.
- A selected receipt's projection cannot replace its canonical body; report limits cannot silently truncate totals or suppress lineage failures.
- A typed dispatch refusal must retain its registered code through the kernel, operator outbox and evidence projection.
- Diagnostic rendering cannot disclose configured credentials or turn local budget/shape failures into a misleading signing failure.

## Task 1: Repair the kernel dispatch rejection seam (RP2)

**Files:** Kernel `kernel/active_response_dispatch.rs`, `active_response_executor.rs`, `active_response_coordinator.rs`, `active_response_committed_recovery.rs`, `error.rs`; control-plane `security/event_consumer/admission_request.rs` and owning tests.

**Interfaces:** Preserve `prepare_kernel_dispatch(...) -> Result<ResponseDispatchCommitRequest, ActiveResponseExecutorError>`. Add `ActiveResponseExecutorError::DispatchRejectedBeforeCommit(DispatchRejection)` and `KernelError::ResponseDispatchRejected(DispatchRejection)`. Preserve unrelated readiness/unknown-outcome behavior. `KernelError::report()` returns the original registered refusal URN.

- [ ] Reproduce mismatched capability and out-of-window lease refusals through the actual preparation/authority path; assert their distinct codes and zero durable dispatch/effects.
- [ ] Carry `StateMachineError::InvalidDispatch` without formatting, retain its error source, and map it at execution, readback, fence and fresh admission boundaries.
- [ ] Assert operator error/outbox and signed evidence projections preserve the discriminant. Run the complete affected kernel/control-plane test targets and strict owning Clippy.

## Task 2: Contain remote MCP ingress and nested client waits (PB4)

**Files:** MCP adapter ingress budget and structural admission modules; remote HTTP/session/factory input owners; edge runtime messaging, roots and nested-flow owners; owning transport/session/runtime tests.

**Interfaces:** Extract the existing structural counter and non-cloned reservation into a reusable MCP ingress owner. Keep its 8 MiB wire, 1,048,576-node and 8 MiB decoded-text aggregate ceilings. A bounded inbox transfers an owned accounted message, including its reservation. Use nonblocking admission under lifecycle locks. Use the existing absolute `AuthorityDeadline` for every client reply wait.

- [ ] Reproduce real roots initialization with a withheld reply and notification accumulation; prove no tool invocation is needed.
- [ ] Preserve one reservation through fresh/restored remote sessions, edge inbound delivery and deferred storage. Release it exactly once on handling, failed send, disconnect or shutdown. Keep cancellation/reply control delivery bounded and available.
- [ ] Bound direct ingress/deferred paths and apply one absolute deadline across unrelated traffic. Preserve lifecycle, authority expiry and clock-fault refusals.
- [ ] Execute exact-limit/one-over, dense/escaped JSON, transfer/drop, cancellation/reply, wall/monotonic expiry and healthy-followup regressions plus the complete affected owner suites.

## Task 3: Bound and qualify storage report work (SR2, SR3, SR4)

**Files:** `security_state/capability_set_suspension.rs`; shared `receipt_store/reports/read_boundary.rs`; analytics integrity/query and cost-attribution owners; owning tests; report guarantee documentation.

**Interfaces:** Preserve existing public query signatures and admin read authorization. Introduce a shared bounded snapshot/read owner for row, raw/decoded byte, group, lineage and SQL work accounting. Exhaustion returns an explicit error, never a partial report. Keep full suspension-key discovery until an authenticated candidate index exists.

- [ ] Reproduce historical suspension growth, unbounded cost-report materialization, selected projection corruption and swallowed lineage errors.
- [ ] Stream suspension discovery and report rows within one pinned transaction; bound metadata before allocation and propagate integrity/lineage failures. Do not authenticate only an untrusted membership-index match.
- [ ] Compare all selected report projections actually used with the canonical receipt body before aggregation. Derive selected financial results from verified bodies.
- [ ] Exercise row/byte/group/SQL/lineage capacity, snapshot consistency, selected projection drift and valid report compatibility in the complete owning suites.
- [ ] Correct the source review's overstated external-mutation guarantee. An embedded receipt signer and selected-row validation do not prove exclusion completeness or independent kernel trust. Preserve that separate acceptance explicitly; do not invent a complete authenticated index subsystem as a side effect of this repair.

## Task 4: Repair unsigned A2A and local diagnostic contracts (PR2/PB2, PB6, GT2, GT4)

**Files:** A2A `auth.rs` and raw HTTP peer tests; ACP compliance and CLI certificate error rendering; OpenAPI local diagnostics and owning tests; Lambda SDK release profile; control-plane guard credential configuration and tests.

**Interfaces:** Use duplicate-aware `decode_document` for unsigned HTTP envelopes while keeping embedded authoritative verification strict. Compliance failure categories select registered, input-independent codes. Operator-local OpenAPI detail is bounded and escaped; public peer rendering stays redacted. Configured API-key Debug is redacted and secret ownership wipes on drop. Standalone Lambda release builds enable overflow checks.

- [ ] Reproduce ordinary decimal/scientific A2A responses, nested duplicate rejection and the current misleading compliance/OpenAPI reports.
- [ ] Repair the owning envelope reader and local diagnostic category propagation. Run real HTTP response and CLI/report regressions, including valid peers and redacted peer errors.
- [ ] Add secret sentinel regressions before changing Debug/custody; preserve policy decoding and legitimate external guard construction.
- [ ] Verify the Lambda standalone release profile through the existing build-profile contract and run all affected owner suites plus strict Clippy/formatting.

## Task 5: Reconcile evidence/product readiness obligations

**Files:** Authoritative landing ledger, status references and source-specific audit records; exact affected owners from the completed review inventory.

- [ ] Reconcile EV3/EV4 refusal evidence, certificate/session-history completeness, ordinary SIEM payload privacy, guard composition, inherited PR threads and operational acceptance against current source and supported claims.
- [ ] Give every verified residual a concrete source repair, verification evidence, remaining acceptance and landing destination. A containing commit or transferred thread is not a finding closure.
- [ ] Repair any confirmed P0/P1 before source freeze and finish actionable P2 owners in dependency order. Record unsupported claims and genuine external acceptance separately; do not declare the whole roadmap complete from this batch.
- [ ] Obtain one fresh independent review of the complete resulting diff and repair all confirmed P0/P1/P2 findings with regression evidence.
- [ ] Refresh incoming #1160 review comments, review documents and the remote
  source/base tuple while repairs continue and again before final acceptance.
  Bind every new finding to its reviewed source, verify it against the current
  candidate, retain its disposition/regression evidence, and repair all confirmed
  issues. A later source or documentation push requires refreshed input binding;
  an older review does not approve that changed candidate.

### Final reconciliation additions

The bounded reconciliation of the original review records found two additional
current Medium/P2 source defects outside the first 19 mapped requirement IDs.
They join Task 5 before source freeze; they are repairs of existing readers and
adapter diagnostics, not new features.

- [ ] RC2: preflight terminal record count and actual stored byte lengths before
  copying or decoding `admission_operation_terminal_records` in the owning
  projection reader. Decode with its existing 1 MiB record ceiling, preserve the
  complete signed manifest comparison and refuse partial/oversize results.
  Exercise actual malformed/oversize storage and a healthy sealed projection.
- [ ] CA6: preserve native filesystem, local peer and config parser causes in the
  Docker and repository broker adapters. Keep fail-closed behavior, registered
  public categories and peer redaction. Verify real local producer failures and
  the owning operator/source chain without exposing credential or path text.

The selected RC2 repair also covers pre-copy stored text metadata at the existing
512-byte identifier/fence/enum ceiling and 64-byte digest/operation-ID contract.
SQLite character-length checks do not substitute for actual byte checks before
owned strings. Record the metadata regression separately from the original nine
payload/count controls.

The hosted roots test exposed a separate transport-contract question: the
declared [MCP 2025-11-25 transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
requires accepted client responses/notifications to return 202 without a body.
Before changing the assertion to the current 200/SSE behavior, reconcile the
actual selected hosted contract. Preserve accounting, overflow, session ownership
and notification delivery; do not qualify a protocol deviation by widening the
test expectation.

The broader RC2 reader census and CA6 cause-provenance debt retain their original
acceptance. These concrete fixes do not close every consumer based on a lexical
count or a containing commit.

## Task 6: Complete exact-candidate qualification and protected landing

- [ ] Retain the stopped/expired controller and historical GitHub runner outage separately from source defects. Availability has recovered; recheck it before final qualification. Select the final source only after all component checks and source corrections pass.
- [ ] Reverify local/remote/PR source, base/merge tuple, workflow parity, modes, immutable definition pin and stable configuration before a fresh event.
- [ ] Execute all seven cold mutation shards and the complete 35-campaign/28-case/64-path aggregation. Authenticate the exact complete artifact before importing only its allowed patch.
- [ ] Obtain genuine native capture/signing, authenticate its three files and policy, verify local evidence descendant E, and configure authentic E/policy before its first push. Follow the existing two-stage S/E publication order.
- [ ] Obtain terminal exact E/M checks, independent review, trusted publication and required native/platform acceptance. Activate the required strict trusted merge contexts without bypass and merge only the qualified candidate.

## Execution ruling

The user explicitly requested plans followed by execution and now permits 6.1 Sol max agents. Continue the existing authorized repair/landing project without another planning approval menu. The earlier automatic source-d049 recovery request is stopped before preparing this batch; the official availability monitor continues. User intent changes which code defects must be addressed, not the evidence or protected landing requirements.

## Incoming October 6 review and shared ownership

The exact review source is `5696c4cf04a1a8368ef36dd51618ea1bd5f7fbfc`; its four documents are preserved in `docs/reviews/2026-10-06-pr1160/`. The authoritative ledger now retains all original1609 records and adds115 findings and10 architecture follow-ups (1734 total). Every newly confirmed boundary discovered during independent review belongs to its parent finding until separately recorded; source integration never establishes qualification.

Use `coord/pr1160` in `/home/connor/lanes/pr1160-coord` for current ownership. Codex alone writes and pushes the integration branch. Claude hands off source commits from its own branch. The board assigns72 findings to this landing and43 preserved later obligations; architecture remains a sequential follow-up. All P0/P1, landing blockers and now-scoped P2 must be repaired before the foundation can land. Preserve later valuable work and branch histories.

The required source waves are keyring namespace/key/ACL custody, money compensation and durable recovery, kernel reservation/cancellation/approval lifecycle, bounded native history, authenticated input/clock ownership, provider/ACP/MCP gates and durable reader consistency. Independent review already found further keyring cross-log conflicts, broker Execute cause loss, provider lifecycle/call-set gaps and unbounded ordinary archive coverage; preserve their original failures and require corrected real owning controls.

Trusted runtime changes need a separate prerequisite based on main `c009aced79d69f01880b5f7c53ed3c1754e3b7da`. The ten-file definition/auditor cut changes prepared main concurrency and authenticated CI run identity without importing the foundation's Rust/Cargo/job workload. Its independent review, protected checks and exact hosted acceptance are prerequisites. Foundation-side checker, nextest separation, seccomp provenance and final source fingerprints stay in the foundation batch. The active landing queue remains at most two PRs.

For efficient feedback, the single Cargo driver runs a warm owning `cargo check --tests` after complete interface/module handoffs, then exact listed runtime targets. No build against an explicitly partial producer is qualification. Held, hung, compiler-only, failed, ignored and unavailable attempts retain their exact categories. Source-specific native Linux/x86_64 and Darwin acceptance, then frozen native/cold/trusted/hosted qualification, remain required; ARM compilation and historical native logs do not replace them.

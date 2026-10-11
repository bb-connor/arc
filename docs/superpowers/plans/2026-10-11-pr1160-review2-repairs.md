# PR 1160 second review repair implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development to implement one independently verified finding at a time. Root owns every integration push.

**Goal:** Repair confirmed review2 findings while collecting the current CI run, then qualify one replacement candidate.

**Architecture:** Keep the current production boundaries and reuse their existing custody, resource-budget and cancellation primitives. Each repair is isolated with its own negative and healthy controls, reviewed before composition; do not introduce broad refactors or compatibility shims.

**Tech Stack:** Rust/Tokio/SQLite, existing Python and Go SDKs, existing CI contract checks.

**Spec:** Frozen review at `974f22914bd339a62933831650c3d55dbaf76987`, `/home/connor/lanes/review2-pr1160/findings.md`, SHA256 `6350c0cc608d13f228e5c8b324b11a9fe72d4d5e3b2eed551846a77019a64eee`. The report is source reasoning, not executed reproduction. Its sibling verification documents identify prerequisites and excluded paths.

## Global constraints

- Root is sole integrator/pusher; claim exact paths in the coordination mailbox before edits.
- Claude independently re-verifies P0/P1 and reviews Root source; repair ownership below prevents duplicate edits.
- Preserve fail-closed behavior, canonical signed bytes, durable accounting and queued-versus-started distinctions.
- No raised limits, test exclusions, ratchet waivers, proof campaigns or authorization-variable mutation.
- Use bounded temporary fixtures. Native-only findings require native evidence; a skipped test is not a pass.
- Keep the two local build slots and private targets; share warm target ownership explicitly, never concurrently.
- Four required hosted checks must pass on the eventual exact head; classify other failures and answer review threads. Connor must give a new merge go-ahead.
- `974f22914b` MSRV failed before compilation due its stale no-fail-fast assertion. Repair is staged as `5955d1cc6a`; retain the original failure and collect the rest of the run.

## Review focus

- Valid ordinary startup and shared budget configuration must retain their intended authority.
- Bounds apply before buffering or branching, including skipped entries and refused requests.
- Cancellation stops queued work while preserving reconciliation for started work.
- Descriptor custody includes platform ACL authority without weakening legitimate systemd credentials.
- Recovery preserves authenticated old state, exact retry semantics and failure evidence.

## Per-finding execution

For each row below: read its frozen source and verifier, establish an exact bounded negative control, implement the smallest approved correction, and run the focused owning tests plus strict lint. Preserve the Original, changed-source hashes, command and output hashes. Update each checkbox only after its evidence exists. Inherited findings retain their provenance and need explicit disposition, not silent dismissal.

### R2-001: Supervisor accepts Darwin credentials with authority-granting ACLs

**Severity:** P0. **Owner:** Root.

**Files:** `crates/products/chio-cli/src/supervise/credentials.rs`, `crates/products/chio-cli/src/supervise/descriptor_credentials.rs`.

**Required correction:** Apply the existing Darwin descriptor ACL authority check to both loaders before accepting bytes or descriptors. Inspection errors and allow/unknown authority must refuse. Preserve genuine Linux systemd handling and deny-only ACL acceptance; add native tests at the actual loaders.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-002: Durable API Protect discards the configured shared budget authority

**Severity:** P1. **Owner:** Claude.

**Files:** `crates/products/chio-api-protect/src/proxy/mediated.rs`, `crates/products/chio-api-protect/src/proxy/state.rs`, `crates/platform/chio-store-sqlite/src/admission_operation_store.rs`.

**Required correction:** Refuse incompatible external budget configuration before provisioning, or explicitly select one composite authority for probes, admission and settlement. Preserving old shared usage requires a qualified state transition; do not silently reset, copy or replace accounting.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-003: Valid keyring-backed trust service configurations always fail startup

**Severity:** P1. **Owner:** Claude.

**Files:** `crates/platform/chio-control-plane/src/trust_control/service_runtime/init.rs`, `crates/platform/chio-control-plane/src/trust_control/cluster/consensus.rs`, `crates/platform/chio-control-plane/src/trust_control/service_types/config.rs`.

**Required correction:** Keep direct seed access removed. Separate bootstrap custody validation from runtime configuration/token validation, and use the latter for cluster composition and request authentication. Exercise full healthy keyring startup, not just isolated constructors.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-004: Cage admission buffers an entire directory before enforcing its scan limit

**Severity:** P1. **Owner:** Root.

**Files:** `crates/security/chio-cage/src/linux.rs`.

**Required correction:** Pass a remaining entry/byte budget into the shared enumerator and refuse before pushing beyond it. Count skipped entries and bound the aggregate walk before sorting.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-005: Temporal rule expansion is exponential before its candidate cap runs

**Severity:** P1. **Owner:** Root.

**Files:** `crates/security/chio-quarantine/src/correlation.rs`, `crates/security/chio-quarantine/src/rules.rs`.

**Required correction:** Enforce the partial-candidate budget on each unique insertion and before intermediate-vector growth. Suppress/refuse immediately on exhaustion. Add a combined branching-plus-reuse control.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-006: Identical uncovered tool calls execute repeatedly for one throttle unit

**Severity:** P1. **Owner:** Root.

**Files:** `crates/security/chio-security-kernel/src/session_throttle.rs`, `crates/platform/chio-store-sqlite/src/security_state/session_throttle.rs`.

**Required correction:** Use a kernel-owned dispatch-attempt identity. Permit free replay only for an authenticated retained operation whose execution cannot repeat; otherwise consume again or deny.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-007: Dropping a timed-out blocking adapter leaves its queued invocation runnable

**Severity:** P1. **Owner:** Root.

**Files:** `crates/kernel/chio-kernel/src/runtime/blocking_connection.rs`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs`.

**Required correction:** Give the adapter ownership of an abort-on-drop guard for each nested queued handoff. Avoid nested pool self-starvation using the existing dispatch boundary. Preserve the distinction between cancelling queued work and reconciling work that already started.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-008: Unbounded broker DNS blocks control work and can hold global secret custody

**Severity:** P1. **Owner:** Claude.

**Files:** `crates/security/chio-secret-broker/src/generic_https.rs`, `crates/security/chio-secret-broker/src/service/custody/registration.rs`, `crates/security/chio-secret-broker/src/generic_https/rustls_transport.rs`.

**Required correction:** Include DNS in one enforceable end-to-end preparation deadline and resolve outside the custody mutex. Avoid a second unconstrained lookup while retaining checked destination pinning. A timeout around an uncancellable worker alone does not bound retained work.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-009: Hermes guest can exhaust its privileged model relay before admission

**Severity:** P1. **Owner:** Root.

**Files:** `sdks/python/chio-hermes/src/chio_hermes/model_relay.py`, `sdks/python/chio-hermes/src/chio_hermes/restricted.py`.

**Required correction:** Bound connections before spawning handlers, enforce body deadlines, and bound retained event count/bytes including refusals. Refuse further traffic when evidence capacity is exhausted; do not silently truncate and claim complete capture.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-010: Abandoned prepared broker connections retain secret entries and capacity

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/security/chio-secret-broker/src/service/ipc/prepared.rs`, `crates/security/chio-secret-broker/src/service/custody/registration.rs`.

**Required correction:** Bind transport abandonment to the exact retained operation and sweep expired pre-capture entries even in an idle daemon. Reuse a bounded cadence on the existing worker with no new wire operation; preserve captured/later operation ownership and accounting. Unconditional EOF deletion/refund is unsafe.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-011: Runtime JSON stores can successfully write a file they refuse to reopen

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/kernel/chio-runtime-core/src/store/json.rs`, `crates/kernel/chio-runtime-core/src/store/trust_floor.rs`.

**Required correction:** Use one backend size constant, serialize an isolated candidate including its newline, refuse before publishing oversized bytes, and publish live state only after successful persistence.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-012: Cage artifact opening can block on a FIFO before rejecting its type

**Severity:** P2. **Owner:** Root.

**Files:** `crates/security/chio-cage/src/linux.rs`.

**Required correction:** Open non-directory artifacts with O_NONBLOCK and O_NOCTTY, then reject non-regular descriptors before reading. Preserve strict resolution and descriptor identity; a path stat before open is insufficient.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-013: Mobile replay-store custody never checks Darwin ACL authority

**Severity:** P2. **Owner:** Root.

**Files:** `crates/trust/chio-custody-hw/src/mobile_challenge/sqlite.rs`.

**Required correction:** Check retained parent and database descriptors for authority-granting Darwin ACLs during initial and subsequent custody validation. Reuse the existing descriptor inspection boundary and fail closed on inspection errors; do not add another FFI implementation.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-014: Simulation rejects valid repeated effects against one captured target

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/core/chio-response-model/src/simulation.rs`, `crates/platform/chio-store-sqlite/src/security_state/response_simulation.rs`.

**Required correction:** Validate each effect's base against the immutable captured state, then apply ordered contributions to the working copy. Alternatively explicitly forbid the combination consistently in validation/builders/schema if it is unsupported.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-015: Go manifest validation copies oversized fields before its size refusal

**Severity:** P2. **Owner:** Root.

**Files:** `sdks/go/chio-go-http/manifest_validation.go`, `sdks/go/chio-go-http/protocol_validation.go`.

**Required correction:** Apply the shared input size limit before constructing the manifest decoder or copying a property. Keep presence, duplicate and semantic validation.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-016: Anthropic gate returns unevaluated tool content in message_start as safe

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/protocol/chio-anthropic-tools-adapter/src/streaming.rs`.

**Required correction:** Refuse populated initial tool content, or route every allowed initial content item through the same evaluation state machine before release. Keep the existing provider-lifecycle checks.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-017: The Start convenience command drops the accepted current authority pin

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/products/chio-cli/src/cli/dispatch/mod.rs`, `crates/products/chio-cli/src/cli/runtime.rs`.

**Required correction:** Pass the current authority pin through Start and use the same issuer-list construction as its API Protect counterpart. Test the actual command-to-config boundary, not only the helper.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-018: Two tamper tests cannot detect removal of reflected-decision validation

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/security/chio-security-kernel/tests/issuance_freeze.rs`, `crates/security/chio-security-kernel/tests/capability_set_suspension.rs`.

**Required correction:** Use tampered otherwise-allowing replies and assert the precise integrity/reflected-binding refusal at the real adapter. Preserve healthy allow and legitimate deny controls. No new harness is needed.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-019: Interrupted decoy creation leaves a final file that exact retry cannot recover

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/security/chio-decoy/src/materialize.rs`, `crates/security/chio-decoy/src/registry.rs`.

**Required correction:** Complete content and ownership metadata in a private same-parent staging object, fsync, then publish with no-replace semantics and sync the parent. Define bounded staging recovery without deleting an unproven final object.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-020: Portable issuer fetch excludes DNS from its total deadline

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/platform/chio-control-plane/src/trust_control/config_and_public/portable_issuer_fetch.rs`.

**Required correction:** Start one enforceable budget before DNS and carry remaining time into HTTP, using resolution whose lifetime is bounded. Keep checked-address pinning. Merely timing out the await does not reclaim the worker/permit.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-021: Candidate copy bounds ignore Git tree metadata and empty-file count

**Severity:** P2. **Owner:** Claude.

**Files:** `scripts/run-security-execution-container.py`.

**Required correction:** Bound tree-output bytes, entry count and aggregate path metadata before retaining/materializing them. Preserve the existing per-blob and total-content limits. Use the existing runner boundary rather than new qualification tooling.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-022: A completed channel cannot accept its next valid service reservation

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/prepared.rs`, `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/reservation.rs`, `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/terminal.rs`.

**Required correction:** Fence against the observed monotonic lifecycle version in the existing transaction and publication path, preserving exact channel/reservation/snapshot checks. Do not reset the counter or weaken the fence.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-023: Zero-share verifier children have no retained identity bound

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/kernel/chio-kernel-core/src/budget_split.rs`.

**Required correction:** Apply finite per-parent entry and retained-identity byte limits before new insertion, preserving idempotent existing-child checks and live holders. A cached sum improves work but does not bound memory. Reject zero-share authority only if that is the intended schema contract.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-024: Mobile gating exposes a plain Allow for requirements it cannot enforce

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/kernel/chio-kernel-core/src/evaluate.rs`, `crates/kernel/chio-kernel-mobile/src/lib.rs`.

**Required correction:** Expose a clearly non-authoritative portable outcome and require mediated authorization for unsupported requirements, or refuse those matched grants in the mobile gate. Align the offline guide. Avoid a compatibility alias that preserves ambiguous Allow.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-025: RegistryUpdateError stops traversal of retained native causes

**Severity:** P3. **Owner:** Claude.

**Files:** `crates/platform/chio-control-plane/src/passport_verifier.rs`.

**Required correction:** Implement source for the three wrapped-error variants using the retained error; no new error abstraction.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.


### R2-026: Resume HMAC reader omits Darwin ACL custody

**Severity:** P1 sibling. **Owner:** Root.

**Files:** `crates/protocol/chio-mcp-remote/src/remote_mcp/session_resume.rs`, its native reader tests, shared existing descriptor ACL boundary as approved.

**Required correction:** Inspect authority-granting ACLs on the retained descriptor before accepting resume-key bytes. Preserve root/current-owner policy, real Linux systemd credentials, bounded reads and metadata stability. No copied FFI implementation or changed mobile MSRV promise.

- [x] Confirm current source and owning contract.
- [x] Execute native test-only Original `d7c2a7c3e8` (two refusals plus two healthy controls).
- [x] Implement and independently review minimal shared custody repair.
- [ ] Pass native and owning Linux controls, strict lint and composition gates.
- [ ] Compose and record exact-source qualification in the ledger.

## Current execution checkpoint

- Root public head remains `974f22914bd339a62933831650c3d55dbaf76987`: Vet/Deny pass, Build active, MSRV failed before compile. Its repair is private `5955d1cc6a`.
- R2-004 and R2-012 genuine Originals each produced one passing preservation control and one assertion failure at `5aa488acb7`. Repairs are isolated; no green claim yet.
- R2-007 initial test-only compile failure is retained separately; corrected Original `7521410a53` is executing. A compile error is not a reproduced behavioral defect.
- R2-015 private composition `193ef17c75` and `95a3c64953` preserves reviewed source. Renewed Go-inclusive Original fails at the intended size-order assertion; owning 55 top-level tests and 79 subtests plus vet pass, and Root focused composition passes. Claude independent review is pending. Earlier evidence omitted Go source pins and remains explicitly superseded.
- R2-001 native Original `5ef4faacd7` is running on Claude's Mac. R2-013/026 test-only continuation `d7c2a7c3e8` is queued there. Native evidence is required; Linux excludes these controls.
- R2-002 is inherited but stays in scope: refuse an explicit external budget configuration that durable admission cannot honor atomically; enable the valid co-located durable authority without a dummy budget flag. Preserve supported ephemeral behavior.
- R2-003 requires healthy keyring service startup, bootstrap validation and runtime/read validation controls. R2-014 compares against immutable captured state and applies ordered contributions. R2-016 refuses populated initial streaming tool content before forwarding.
- Resolver permits remain owned until actual completion, including after caller timeout; one absolute deadline covers all stages. Relay finalization stops new admission before terminal evidence publication, preserves started work reconciliation and labels unfinished capture unresolved.
- Shared CI content pins remain Root-owned. No cap raise, baseline waiver, authorization rotation or proof campaign. No merge without Connor's new go-ahead.

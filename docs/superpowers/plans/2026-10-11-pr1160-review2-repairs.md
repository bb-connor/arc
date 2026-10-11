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

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-002: Durable API Protect discards the configured shared budget authority

**Severity:** P1. **Owner:** Claude.

**Files:** `crates/products/chio-api-protect/src/proxy/mediated.rs`, `crates/products/chio-api-protect/src/proxy/state.rs`, `crates/platform/chio-store-sqlite/src/admission_operation_store.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-003: Valid keyring-backed trust service configurations always fail startup

**Severity:** P1. **Owner:** Claude.

**Files:** `crates/platform/chio-control-plane/src/trust_control/service_runtime/init.rs`, `crates/platform/chio-control-plane/src/trust_control/cluster/consensus.rs`, `crates/platform/chio-control-plane/src/trust_control/service_types/config.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-004: Cage admission buffers an entire directory before enforcing its scan limit

**Severity:** P1. **Owner:** Root.

**Files:** `crates/security/chio-cage/src/linux.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-005: Temporal rule expansion is exponential before its candidate cap runs

**Severity:** P1. **Owner:** Root.

**Files:** `crates/security/chio-quarantine/src/correlation.rs`, `crates/security/chio-quarantine/src/rules.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-006: Identical uncovered tool calls execute repeatedly for one throttle unit

**Severity:** P1. **Owner:** Root.

**Files:** `crates/security/chio-security-kernel/src/session_throttle.rs`, `crates/platform/chio-store-sqlite/src/security_state/session_throttle.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-007: Dropping a timed-out blocking adapter leaves its queued invocation runnable

**Severity:** P1. **Owner:** Root.

**Files:** `crates/kernel/chio-kernel/src/runtime/blocking_connection.rs`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-008: Unbounded broker DNS blocks control work and can hold global secret custody

**Severity:** P1. **Owner:** Claude.

**Files:** `crates/security/chio-secret-broker/src/generic_https.rs`, `crates/security/chio-secret-broker/src/service/custody/registration.rs`, `crates/security/chio-secret-broker/src/generic_https/rustls_transport.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-009: Hermes guest can exhaust its privileged model relay before admission

**Severity:** P1. **Owner:** Root.

**Files:** `sdks/python/chio-hermes/src/chio_hermes/model_relay.py`, `sdks/python/chio-hermes/src/chio_hermes/restricted.py`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-010: Abandoned prepared broker connections retain secret entries and capacity

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/security/chio-secret-broker/src/service/ipc/prepared.rs`, `crates/security/chio-secret-broker/src/service/custody/registration.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-011: Runtime JSON stores can successfully write a file they refuse to reopen

**Severity:** P2. **Owner:** Root.

**Files:** `crates/kernel/chio-runtime-core/src/store/json.rs`, `crates/kernel/chio-runtime-core/src/store/trust_floor.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-012: Cage artifact opening can block on a FIFO before rejecting its type

**Severity:** P2. **Owner:** Root.

**Files:** `crates/security/chio-cage/src/linux.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-013: Mobile replay-store custody never checks Darwin ACL authority

**Severity:** P2. **Owner:** Root.

**Files:** `crates/trust/chio-custody-hw/src/mobile_challenge/sqlite.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-014: Simulation rejects valid repeated effects against one captured target

**Severity:** P2. **Owner:** Root.

**Files:** `crates/core/chio-response-model/src/simulation.rs`, `crates/platform/chio-store-sqlite/src/security_state/response_simulation.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-015: Go manifest validation copies oversized fields before its size refusal

**Severity:** P2. **Owner:** Root.

**Files:** `sdks/go/chio-go-http/manifest_validation.go`, `sdks/go/chio-go-http/protocol_validation.go`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-016: Anthropic gate returns unevaluated tool content in message_start as safe

**Severity:** P2. **Owner:** Root.

**Files:** `crates/protocol/chio-anthropic-tools-adapter/src/streaming.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-017: The Start convenience command drops the accepted current authority pin

**Severity:** P2. **Owner:** Root.

**Files:** `crates/products/chio-cli/src/cli/dispatch/mod.rs`, `crates/products/chio-cli/src/cli/runtime.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-018: Two tamper tests cannot detect removal of reflected-decision validation

**Severity:** P2. **Owner:** Root.

**Files:** `crates/security/chio-security-kernel/tests/issuance_freeze.rs`, `crates/security/chio-security-kernel/tests/capability_set_suspension.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-019: Interrupted decoy creation leaves a final file that exact retry cannot recover

**Severity:** P2. **Owner:** Root.

**Files:** `crates/security/chio-decoy/src/materialize.rs`, `crates/security/chio-decoy/src/registry.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-020: Portable issuer fetch excludes DNS from its total deadline

**Severity:** P2. **Owner:** Root.

**Files:** `crates/platform/chio-control-plane/src/trust_control/config_and_public/portable_issuer_fetch.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-021: Candidate copy bounds ignore Git tree metadata and empty-file count

**Severity:** P2. **Owner:** Root.

**Files:** `scripts/run-security-execution-container.py`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-022: A completed channel cannot accept its next valid service reservation

**Severity:** P2. **Owner:** Root.

**Files:** `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/prepared.rs`, `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/reservation.rs`, `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/terminal.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-023: Zero-share verifier children have no retained identity bound

**Severity:** P2. **Owner:** Root.

**Files:** `crates/kernel/chio-kernel-core/src/budget_split.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-024: Mobile gating exposes a plain Allow for requirements it cannot enforce

**Severity:** P2. **Owner:** Root.

**Files:** `crates/kernel/chio-kernel-core/src/evaluate.rs`, `crates/kernel/chio-kernel-mobile/src/lib.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-025: RegistryUpdateError stops traversal of retained native causes

**Severity:** P3. **Owner:** Root.

**Files:** `crates/platform/chio-control-plane/src/passport_verifier.rs`.

**Required correction:** Verify source before choosing the repair.

- [ ] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [ ] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.


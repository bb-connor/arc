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
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-002: Durable API Protect discards the configured shared budget authority

**Severity:** P1. **Owner:** Claude.

**Files:** `crates/products/chio-api-protect/src/proxy/mediated.rs`, `crates/products/chio-api-protect/src/proxy/state.rs`, `crates/platform/chio-store-sqlite/src/admission_operation_store.rs`.

**Required correction:** Refuse incompatible external budget configuration before provisioning, or explicitly select one composite authority for probes, admission and settlement. Preserving old shared usage requires a qualified state transition; do not silently reset, copy or replace accounting.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-003: Valid keyring-backed trust service configurations always fail startup

**Severity:** P1. **Owner:** Claude.

**Files:** `crates/platform/chio-control-plane/src/trust_control/service_runtime/init.rs`, `crates/platform/chio-control-plane/src/trust_control/cluster/consensus.rs`, `crates/platform/chio-control-plane/src/trust_control/service_types/config.rs`.

**Required correction:** Keep direct seed access removed. Separate bootstrap custody validation from runtime configuration/token validation, and use the latter for cluster composition and request authentication. Exercise full healthy keyring startup, not just isolated constructors.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
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

**Required correction:** Use a kernel-owned dispatch-attempt identity. Retain a private random identity on the actual acquired in-flight request, including waits; reused session/request text in a fresh kernel cannot identify an old attempt. Authenticated durable operation identity takes priority. Permit free replay only for retained execution that cannot repeat; otherwise consume again or deny.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

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

**Required correction:** Bound preparation DNS by one absolute deadline, resolve outside the custody mutex, and retain the resolver slot until the underlying lookup actually returns. Acquire nonblocking capacity before spawning. Reuse the checked pinned destination without a second lookup. The existing separate absolute connect/TLS/I/O deadline starts at execution, preserving the signed HTTP timeout semantics.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
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

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-011: Runtime JSON stores can successfully write a file they refuse to reopen

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/kernel/chio-runtime-core/src/store/json.rs`, `crates/kernel/chio-runtime-core/src/store/trust_floor.rs`.

**Required correction:** Use one backend size constant, serialize an isolated candidate including its newline, refuse before publishing oversized bytes, and publish live state only after successful persistence.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

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
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-014: Simulation rejects valid repeated effects against one captured target

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/core/chio-response-model/src/simulation.rs`, `crates/platform/chio-store-sqlite/src/security_state/response_simulation.rs`.

**Required correction:** Validate each effect's base against the immutable captured state, then apply ordered contributions to the working copy. Alternatively explicitly forbid the combination consistently in validation/builders/schema if it is unsupported.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
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

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-017: The Start convenience command drops the accepted current authority pin

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/products/chio-cli/src/cli/dispatch/mod.rs`, `crates/products/chio-cli/src/cli/runtime.rs`.

**Required correction:** Pass the current authority pin through Start and use the same issuer-list construction as its API Protect counterpart. Test the actual command-to-config boundary, not only the helper.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-018: Two tamper tests cannot detect removal of reflected-decision validation

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/security/chio-security-kernel/tests/issuance_freeze.rs`, `crates/security/chio-security-kernel/tests/capability_set_suspension.rs`.

**Required correction:** Use tampered otherwise-allowing replies and assert the precise integrity/reflected-binding refusal at the real adapter. Preserve healthy allow and legitimate deny controls. No new harness is needed.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-019: Interrupted decoy creation leaves a final file that exact retry cannot recover

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/security/chio-decoy/src/materialize.rs`, `crates/security/chio-decoy/src/registry.rs`.

**Required correction:** Use one validated private internal staging directory on the same device. Tag the newly created inode before writing, then fsync and publish with no-replace semantics, syncing both parents. Authenticate non-empty staging objects before reclaiming; recover the empty create-before-tag state only within enforced internal-directory custody. Check descriptor ACL authority on Darwin. Preserve every unproven final object and test each interrupted-write stage.

**Descriptor ownership:** The dependency gate forbids the decoy engine from reaching platform crates. Move the existing Darwin ACL inspector and its tests unchanged from `chio-sqlite-file-identity` into the small core `chio-file-custody` utility, depending only on `libc`. Existing consumers call that owner directly; SQLite VFS inspection remains in its original crate. Root owns workspace/lock updates and the decoy hook after Claude releases its staging repair. Verify unchanged inspector bytes, dependency layering, portable tests, strict lint and native Darwin controls before publication.

**Concurrent retry:** Each materialization opens and locks a fresh validated staging-directory descriptor nonblockingly before touching the stage or verifying an existing final file. Keep that descriptor alive through file and directory syncs and receipt verification. Contention returns the existing typed `Io(WouldBlock)` error. Preserve the genuine two-caller Original, same-instance contention, unchanged stage inode/content, exact final receipt and descriptor-drop recovery controls.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

The corrected NUL-terminated staging domain has matching native Darwin renewal
(70 tests, five full reruns and strict lint). Its Linux owning, strict and actual
deception-boundary renewal is pending; prior domain evidence remains historical.

### R2-020: Portable issuer fetch excludes DNS from its total deadline

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/platform/chio-control-plane/src/trust_control/config_and_public/portable_issuer_fetch.rs`.

**Required correction:** Start one enforceable budget before DNS and carry remaining time into HTTP, using resolution whose lifetime is bounded. Keep checked-address pinning. Merely timing out the await does not reclaim the worker/permit.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

Source is privately integrated with independent review; the fixed-pool contract
bounds retained work without hard cancellation. Final Originals and owning/strict
evidence are pending. Initial Tokio blocking-queue time is outside the fetch budget.

### R2-021: Candidate copy bounds ignore Git tree metadata and empty-file count

**Severity:** P2. **Owner:** Claude.

**Files:** `scripts/run-security-execution-container.py`.

**Required correction:** Bound tree-output bytes, entry count and aggregate path metadata before retaining/materializing them. Preserve the existing per-blob and total-content limits. Use the existing runner boundary rather than new qualification tooling.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [x] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [x] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [x] Compose into the replacement batch and reconcile its ledger state.

### R2-022: A completed channel cannot accept its next valid service reservation

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/prepared.rs`, `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/reservation.rs`, `crates/platform/chio-store-sqlite/src/channel_lifecycle_store/terminal.rs`.

**Required correction:** Fence against the observed monotonic lifecycle version in the existing transaction and publication path, preserving exact channel/reservation/snapshot checks. Do not reset the counter or weaken the fence.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-023: Zero-share verifier children have no retained identity bound

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/kernel/chio-kernel-core/src/budget_split.rs`.

**Required correction:** Bound per-parent child count and retained child-ID bytes, plus registry totals of 10,000 parents, 100,000 child edges and 16 MiB of actually owned IDs. Keep exact counters and idempotent known admissions. Reclaim only signed-expired parents with no live lease holders using the existing trusted kernel clock. Preserve non-expiring operator registrations and fail closed on clock failure. Keep the generic trait contract stable through an additive concrete-registry path where possible; no wire/config schema expansion.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-024: Mobile gating exposes a plain Allow for requirements it cannot enforce

**Severity:** P2. **Owner:** Claude.

**Files:** `crates/kernel/chio-kernel-core/src/evaluate.rs`, `crates/kernel/chio-kernel-mobile/src/lib.rs`.

**Required correction:** Expose a clearly non-authoritative portable outcome and require mediated authorization for unsupported requirements, or refuse those matched grants in the mobile gate. Align the offline guide. Avoid a compatibility alias that preserves ambiguous Allow.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.

### R2-025: RegistryUpdateError stops traversal of retained native causes

**Severity:** P3. **Owner:** Claude.

**Files:** `crates/platform/chio-control-plane/src/passport_verifier.rs`.

**Required correction:** Implement source for the three wrapped-error variants using the retained error; no new error abstraction.

- [x] Confirm current source and owning contract; record disputed scope precisely.
- [ ] Establish a bounded failing control on the unchanged predecessor.
- [x] Implement and review the minimal correction; preserve healthy and denial paths.
- [ ] Pass focused owner tests and strict lint; record native/unavailable evidence distinctly.
- [ ] Compose into the replacement batch and reconcile its ledger state.


### R2-026: Resume HMAC reader omits Darwin ACL custody

**Severity:** P1 sibling. **Owner:** Root.

**Files:** `crates/protocol/chio-mcp-remote/src/remote_mcp/session_resume.rs`, its native reader tests, shared existing descriptor ACL boundary as approved.

**Required correction:** Inspect authority-granting ACLs on the retained descriptor before accepting resume-key bytes. Preserve root/current-owner policy, real Linux systemd credentials, bounded reads and metadata stability. No copied FFI implementation or changed mobile MSRV promise.

- [x] Confirm current source and owning contract.
- [x] Execute native test-only Original `d7c2a7c3e8` (two refusals plus two healthy controls).
- [x] Implement and independently review minimal shared custody repair.
- [x] Pass native and owning Linux controls, strict lint and composition gates.
- [x] Compose and record exact-source qualification in the ledger.

## Current execution checkpoint

- Published 974f22914b remains unchanged. Vet and Deny passed; Build and MSRV failed before compilation on the command fixture repaired privately at 5955d1cc6a.
- Private source 70bf8863d4 includes the reviewed replacement batch, expiry-lock ordering, issuer drain synchronization, relay setup, cold-map duplicate oracle, successor reservation trust time, atomic native markers and custody-fault count-observer classification. The canonical ledger preserves 2,005 requirements and all historical evidence.
- Composed e4bc85e479 control-plane campaign: 1,968 passed, three failed, one ignored. The three failures have reviewed fixture corrections awaiting focused renewal. Custody-election and native cadence controls passed.
- Store campaign: 2,404 passed, two failed, 13 ignored at top level, plus one nested child pass. Both failures have reviewed fixture corrections. Strict all-target owning checks passed on that predecessor; later source needs renewal.
- Linux decoy/file custody passed 70 tests and actual deception passed 108 on e4bc. Domain-corrected native Darwin renewal remains separate. Earlier kernel 1,909 pass/two ignored, corrected core 90 pass and API Protect 280 pass are retained source-specific results.
- Earlier cf46 CLI diagnostic: 1,444 passed, 72 failed, seven ignored. Exactly 70 need unavailable local Linux x86_64 enforcement. Export readiness is source-repaired; intermittent proof-package/report hash drift remains under diagnosis. Repeated healthy controls do not explain its prior failure.
- Native predecessor trace classified five expired captures and one empty-marker race. The marker repair is reviewed. Final serial portable and eight-thread acceptance must use the composition containing the history-checkpoint correction.
- Cold-map preparation remains test-only. Durable persistence, trusted-root attachment, atomic activation and G5 readiness remain open. Fixed-five cadence does not establish ten-second production latency or cold-open cost. Preserve 903189, e017687 and ed3f1a independently.
- Focused renewals: expiry3, issuer30, authority/custody88, reservation6, snapshot151 at eight threads (seven ignored retained), CLI14+147, actual broker portable, native13 at eight threads, cold26/mutation, and strict affected owners. No cap raise, baseline waiver, authorization rotation or proof campaign. Four exact-head required checks, classified other failures and answered threads remain the landing bar.

## Fourth review follow-up

- R4-001 (Claude C2): `66f60d853d` is composed at `00b23066f1` and source-approved. The deterministic clock observes registry ownership at sampling, with exact expired-parent refusal and no insertion. Genuine Original, repaired runtime and strict/clock checks remain pending.
- R4-002 (Root): exact helper inventory corrected by `8781b9b176`; genuine Original failure retained; repaired focused/full parent selftests pass. Claude approved the source and evidence at 04:45:30Z.
- R4-003 (Claude C3, Root integration): `d3669ed272` uses one worker and two test-only slots for the expired job and its FIFO observer. Runtime renewal pending; production bounds and all no-start assertions remain unchanged.
- R4-004 (Root): `9d07df2675` tests duplicate identity/outbox rows in an otherwise valid five-row Grant. Retain predecessor-oracle and removed-duplicate-guard controls, final cold-map tests and strict lint before acceptance.

The canonical ledger now preserves 2,005 requirements, including the relay and snapshot fixtures and named issuer refusal-provenance follow-up. These rows extend the same replacement batch and do not open another landing PR.

### CI proof parity follow-up (2026-10-11)

The unchanged cf46 CLI reproduces intermittent package/report hash mismatch under 16 concurrent fixture generations. Retained outcome blobs identify nonzero `elapsed_millis` from ambient `Instant` reads in ordinary and nested kernel evaluation; the harness injects a fixed authority clock, but those elapsed observations bypass it. This is a production determinism defect exposed by the fixtures, not permission to weaken proof hashes.

- Claude C7 owns the isolated Rust repair and both-path success, clock-failure and regression controls. Measure elapsed time through the injected monotonic clock with checked subtraction. Preserve committed operation custody before any fallible read and preserve recovery on post-dispatch error.
- Root owns the existing clock gate and its calibration. Include ambient monotonic reads throughout the kernel evaluation directory, including aliases and new helper modules; retain existing watchdog scope and all inventory limits.
- Root gate calibration: unchanged scanner misses 18 bounded subcases; the repaired scanner passes all 13 calibration tests and rejects both known unchanged production sites. The full source gate remains intentionally failing until the Rust repair is composed.
- Require retained Original evidence, focused owning tests and strict lint, source review, complete CLI proof fixture suite, and a repeat of the same concurrent artifact-equality control before publication. Preserve partial parity-stage evidence separately from end-to-end fixture collection.
- Classify and diagnose the separate commit-writer startup denial without weakening fail-closed admission. No new proof campaign or authorization mutation.


## Final clock interaction and writer readiness

The full `66d4568ab7` kernel campaign produced 1,919 passes, one failure and two
ignored tests. Preserve that failed campaign. The sole failure is the existing
non-durable signed-value/cost contract from `5ead9f7d59`: the new elapsed end read
unnecessarily consumes a clock fault after the value has been observed.

- Root repair `94d7c3ae74` samples the end clock only for a durable admission or a
  stream. Ordinary values have no elapsed consumer and keep their signed receipt
  and cost. The existing assertions stay; new assertions prove the end clock was
  not read, while both non-durable stream paths require measured duration.
- Claude source review approves the repair. Renew the ordinary three-case family,
  durable ten-case matrix, runtime-harness owner, CLI proof contracts and strict
  affected-owner checks. Prior full and native campaigns retain their exact sources.
- Writer readiness producer `ebbbacbeb5` is integrated as `a7cedf21d9`. The harness
  uses the existing bounded readiness barrier before admission. Existing one-shot
  held/failed-seed tests cover timeout, refusal and successful release. No test hook,
  production store behavior, timeout allowance or gate is changed.
- The old writer probe yielded zero writer refusals in 208 attempts and 17 known
  pre-repair parity failures. This is a source-backed startup-race repair; do not
  call it a reproduced explanation of the historical uninstrumented refusal.

Publish one successor after changed-boundary renewal and remaining failure
classification. Require the four exact-head hosted checks and answered threads,
then report the head and disclosed post-merge obligations for merge authorization.

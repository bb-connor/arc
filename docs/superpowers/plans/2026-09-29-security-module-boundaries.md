# Security module boundaries and confinement helper implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan inline. The user approved this complete batch and requested minimal delegation.

**Goal:** Replace textual assembly at the four approved security owners with compiler-enforced privacy, and isolate the privileged confinement helper's dependency graph.

**Architecture:** Keep public protocol contracts stable while placing construction, validation, persistence, transport, and orchestration in named private modules. Move helper plan/envelope contracts into a small shared crate and child bootstrap into `chio-cage-init`; the parent launcher retains custody and evidence verification.

**Tech Stack:** Rust 1.94.1, Cargo, SQLite, Linux descriptors, Landlock, seccomp, Python and shell repository gates.

**Spec:** Packet 7 of `2026-09-26-security-engineering-excellence.md`, H11 of `../specs/2026-09-26-hardening-toolchain-spec.md`, and `docs/security/engineering-standard.md`.

## Global constraints

- Preserve signed bytes, schemas, runtime decisions, test cases, fail-closed validation, and public port contracts.
- Use responsibility names, private modules, explicit imports, and the narrowest usable visibility. No compatibility implementation or duplicate validator.
- Separate mechanical relocation, visibility restriction, and formatting commits. Ratchet hygiene caps through the gate.
- Preserve async-signal-safe pre-exec closures and seccomp default denial at compilation, serialization, and installation.
- Work on `packet/3-retention-accounting` in `/tmp/arc-security-launch`. Preserve preexisting `output/`.
- Batch implementation and focused checks; no full-workspace campaign without a concrete integration reason. Disable incremental compilation to bound disk use.

## Review focus

- Private validated types cannot be constructed by orchestration or transport siblings.
- Module moves retain every test, cfg condition, error classification, and signed-byte projection.
- SQLite mutation helpers remain within the security-state owner and transaction guard.
- Helper plan validation and FD custody do not diverge between parent and child.
- Production helper features and packaging build the isolated crate; forbidden dependencies fail the budget gate.

### Task 1: Security ports

**Files:** Replace `crates/security/chio-security-types/src/ports_parts/*` with named modules under `src/ports/`; update `src/ports.rs`.

**Interfaces:** Preserve the public `ports::*` API and no-std support; move private validation and commitment helpers into their responsible modules.

- [ ] Capture existing inventory and declaration boundaries; relocate complete Rust items without logic changes.
- [ ] Restrict construction and helper visibility; keep public reexports explicit.
- [ ] Run security-types unit/integration tests and no-default-features check. Expected: passing, unchanged test inventory.
- [ ] Commit mechanical relocation, privacy, and formatting separately.

### Task 2: Broker service

**Files:** Replace `crates/security/chio-secret-broker/src/service_parts/*` with named service execution, failure, sensitive wire, IPC deadline/lifecycle/prepared/response, and test modules.

**Interfaces:** Preserve `BrokerService`, IPC framing, bounded zeroizing parsing, prepared dispatch and durable failure projections. Do not expose secret-bearing fields beyond their owner.

- [ ] Relocate complete items and tests, retaining typed rejection and absolute-deadline behavior.
- [ ] Restrict internal helpers to service or IPC ownership and retain private parser state.
- [ ] Run broker unit tests excluding the separately qualified process campaign; explicitly exercise wire, authority-time, prepared IPC, and deadline cases. Expected: passing inventory and no secret ownership regression.
- [ ] Commit relocation, privacy, and formatting separately.

### Task 3: SQLite security state

**Files:** Replace `crates/platform/chio-store-sqlite/src/security_state_parts/*` with schema, store, codec, event/correlation, lineage, scheduler/response/dispatch, and outbox modules under `src/security_state/`.

**Interfaces:** Preserve `SqliteSecurityStateStore` and existing native transaction adapters. Keep connections and lifecycle custody private to security state.

- [ ] Move declarations and implementations into their responsibility owners; preserve SQL and integrity checks byte-for-byte.
- [ ] Restrict sibling access through `pub(super)` and narrow explicit exports.
- [ ] Run SQLite security-state, native flow, response, correlation, deadline, and retention owner tests. Expected: passing, unchanged test inventory.
- [ ] Commit relocation, privacy, and formatting separately.

### Task 4: Control-plane security composition

**Files:** Remove textual assembly from active response, event consumer, scheduler worker, adapters/effect port, and their included tests under `crates/platform/chio-control-plane/src/security/`.

**Interfaces:** Preserve existing production adapter and orchestrator APIs, effect ownership, admission checks, and committed recovery.

- [ ] Cut implementation and test support into named modules, update imports and narrowly scoped test fixtures.
- [ ] Minimize visibility and remove obsolete fragments.
- [ ] Run the control-plane security owner tests and strict Clippy for all four changed owners. Expected: passing, no dropped tests.
- [ ] Ratchet hygiene and commit relocation, privacy, and formatting independently.

### Task 5: Minimal confinement helper

**Files:** Add `crates/security/chio-cage-init` and shared plan/envelope crate; update `chio-cage`, workspace manifests/lockfile, dependency budget, helper build/inventory and packaging scripts.

**Interfaces:** One shared plan/launch/status wire contract and validation implementation. Parent owns launch supervision, child owns bootstrap and confinement. Preserve executable name `chio-cage-init`.

- [ ] Extract helper contracts and child bootstrap; remove the broad cage binary and bootstrap export.
- [ ] Update all helper recipes and test binary discovery to the new package.
- [ ] Measure normal musl graph, set exact ceiling, retire pending dependencies into denials; document the required JSON codec exception.
- [ ] Run gate self-tests including denied-dependency injection, cage/init tests and host compile checks, and measure available helper artifact linkage. Expected: focused checks pass; graph contains no denied dependency.
- [ ] Record native x86_64 enforcement limitations separately from host compile/test evidence.

### Completion

- [ ] One fresh whole-batch review, one fix pass if needed, final focused verification.
- [ ] Record each task's result, evidence, scope rulings, and next batch in a committed execution report.

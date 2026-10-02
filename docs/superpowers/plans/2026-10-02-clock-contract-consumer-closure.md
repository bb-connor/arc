# Clock, decoding contract and consumer qualification closure

**Goal:** Close AC2/AC3 and SF1/CA2 against current code and repair the failed hosted consumer workflow.

**Architecture:** Authority owners share an explicit fallible clock and reject faults before mutations. Native clocks are selected at composition boundaries. Source gates derive coverage from actual trust boundaries, pin decoder contracts and require code evidence for non-baseline claims. Hosted consumer prerequisites are checked before qualification.

**Spec:** AC2/AC3 in `docs/reviews/2026-10-01-execution-review-accounting-clocks.md`; SF1 in `2026-10-01-execution-review-signed-input-frost.md`; CA2 in `2026-10-01-execution-review-campaign-audit.md`; next queue in `2026-10-02-operational-regression-recovery-execution.md` (review paths under `docs/reviews/`); `docs/security/trusted-time.md`.

## Global constraints

- Work only in `/tmp/arc-security-launch` on `packet/3-retention-accounting`; preserve unrelated `output/` and other worktrees.
- Fail closed on clock faults, regressions, overflow and invalid authoritative input. Retain signature, tenant, durable-fence and replay checks.
- Use shared Clock/UnixMillis owners. No ambient wall-clock replacement disguised as another adapter call within an injected owner.
- No new lint allowances, ignored tests, timeout relaxations or dependency exemptions. No production unwrap/expect. No em dashes.
- Serialize Cargo graphs; raw terminal evidence lives outside Git. One final independent review. Existing commit/push and hosted qualification authorization applies; no merge or release activation.
- Checked source contracts are lexical tripwires with explicit limits, never authentication or complete semantic proof.

## Review focus

- Injected epochs far ahead of/behind host time must govern aggregate issuance and all affected mutations consistently.
- Unavailable or regressing clocks must fail before authority mutations and preserve existing durable state.
- Clock aliases, function pointers and native adapters must not escape TCB scope detection.
- A signed/canonical decoder downgrade and inventory-only reclassification must fail independently of old census counts.
- Native consumer setup must fail clearly on missing prerequisites, export only completed executables and retain terminal hosted evidence.

### Task 1: AC2 shared authority time

**Files:** kernel authority/aggregate, clock and remaining ambient consumers; SQLite store owners/recovery/receipt support; CLI process_host composition and native_broker.
**Interfaces:** existing shared `Clock`, `ClockReading`, `UnixMillis`; explicit clocks or readings supplied to validators and store constructors; default native adapters only at constructors.

- [x] Reproduce aggregate epoch mismatch and clock-fault mutation gaps with owner tests.
- [x] Remove kernel global timestamp helpers and thread kernel authority time into finding-pool, active-response, child-receipt and release paths.
- [x] Connect remaining SQLite and process-host clock consumers to injected owners, retaining default constructor convenience and durable high-water semantics.
- [x] Run affected owner tests and integration controls for failure, expiry and recovery.

### Task 2: AC3 actual clock boundary enforcement

**Files:** `scripts/check-security-clocks.py`, its tests/inventory and trusted-time docs.
**Interfaces:** scope derived from trust-boundary inventory and TCB libraries; pinned pre-existing uncovered sites explicitly classified, without claiming new scope debt as migrated.

- [x] Reproduce missing process-host scope, adapter references, aliases and function-path clock reads.
- [x] Enforce actual TCB coverage and explicit composition/remaining-debt classifications.
- [x] Run calibration tests and the real source gate; document remaining scope honestly.

### Task 3: SF1/CA2 checked decoding contracts

**Files:** trust-boundary gate, helper modules, inventory, calibration tests and reader contract documentation.
**Interfaces:** constructor/owner decoding contracts tied to source calls; non-baseline classifications require named source owners and constrained API evidence, not prose alone.

- [x] Reproduce signed/canonical-to-document downgrade and inventory-only baseline reclassification.
- [x] Pin per-owner decoding methods and validate bounded/constrained code evidence for classified raw readers; preserve legitimate unsigned provider/document contracts.
- [x] Add mutation controls for aliases, missing evidence, unrelated functions and inventory-only edits; run the actual source gate.

### Task 4: broader hosted consumer repairs

**Files:** prepared-native-broker and enforced-native-fixture actions, process-workers workflow/tests, process-host Python runner.
**Interfaces:** musl compiler/toolchain, completed executable environment exports, immutable exact-source workflow dispatch.

- [x] Reproduce missing compiler setup and Ruff formatting; trace missing adapter export to build outcome.
- [x] Provision prerequisites at their owning action and validate executable exports; fix formatting without weakening runtime acceptance.
- [ ] Run workflow/script checks, commit and push the source, dispatch the repaired exact-source workflow and retain its terminal result. Repair further failures within this qualification boundary.

### Task 5: review, qualification and publication

**Files:** execution report and compact evidence artifact under `docs/reviews/`.

- [x] Run changed-owner warnings-denied Clippy, formatting and affected source gates.
- [x] Obtain one independent final review, resolve findings with meaningful regressions and verify any fix pass.
- [ ] Publish all authorized security changes, verify remote SHA, record per-task completion and the next remaining queue. Keep local and hosted acceptance distinct.

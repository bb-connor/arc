# Native clock, kernel test and declaration ownership implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline. This batch is authorized; preserve the existing isolated worktree and local-only delivery.

**Goal:** Finish the three approved structural/reliability tasks without changing production authority windows or signed bytes.

**Architecture:** Native-flow fixtures use explicit deterministic authority time, including reopened and subprocess owners. Kernel tests become named modules with private fixtures and narrow sharing. Shared schema/domain identifiers are declared once at their existing dependency owner or lowest common contract owner, then imported directly.

**Tech Stack:** Rust, SQLite, Cargo, Python inventory gates.

**Spec:** `docs/security/engineering-standard.md` rules 1.1-1.5; `docs/superpowers/plans/2026-09-26-security-engineering-excellence.md` Packet 7 and correction 4A; `docs/reviews/2026-09-28-remaining-security-work.md` item 4.

## Global constraints

- No legacy compatibility aliases, changed signed bytes, relaxed expiry checks, production test clocks, or widened production visibility to accommodate mechanical relocation. New clock APIs require an explicit ownership rationale.
- No push, merge, publication or operational activation. Preserve preexisting `output/`.
- Implement inline; one final fresh reviewer. Focused checks govern this batch; full workspace/native x86/hosted qualification remains separately queued.
- Keep mechanical kernel relocation, visibility and formatting commits separate. Preserve every existing test and migrate selectors atomically.
- Keep evidence and explicit remaining acceptance gates in the execution record.

## Review focus

- A reopened or subprocess native-flow owner must use the same authority epoch as the parent.
- Explicit expiry, regression, unavailable-clock and panic tests must still reach their intended rejection boundary.
- Fixture privacy must survive the module cut without exporting mutable internals to the crate.
- Moving tests must preserve cfg predicates and subprocess/test selectors.
- Producer/verifier identifiers must have one owner without a dependency cycle or changed canonical bytes.

### Task 1: Deterministic native-flow authority clocks

**Files:** native-flow fixtures under control plane; kernel clock, evaluation and issuance owners; SQLite admission transaction clocks; broker native readback and IPC; caller executor ledger; clock inventory; batch evidence.

**Interfaces:** Consumes existing `Clock`, `ChioKernel::new_with_clock`, `SqliteAuthorityStore::open_serving_with_clock`, runtime/broker injected clocks and the independent caller executor clock. Produces deterministic fixture setup plus explicit clock advancement. Reproduced failures required repairing kernel and SQLite clock ownership and a read-only SQLite authority-time query for broker adapters; see the execution ledger rulings.

- [ ] Pin the fixture epoch with a failing fixture regression; retain the previous parallel capture-expiry failure as causal evidence.
- [ ] Wire all native-flow authority owners, resolver, runtime, broker and restart paths to deterministic clocks. Preserve deliberate fault clocks and historical-time fixtures.
- [ ] Repair the reproduced production clock bypasses while preserving skew, high-water and expiry checks; cover unavailable, wall-regression, monotonic-regression and stale-caller rejection.
- [ ] Exercise native-flow and nonce replay/capture/restart/expiry cases in parallel, with focused before/after evidence and exact terminal counts. Expected: all selected tests pass, including intended denial tests.
- [ ] Commit the fixture change and verification evidence.

### Task 2: Kernel test responsibility and privacy modules

**Files:** `crates/kernel/chio-kernel/src/kernel/tests.rs`, its child test/support files, selector consumers, hygiene inventory.

**Interfaces:** Consumes existing kernel test helpers; produces responsibility-named child modules and narrowly shared test support. No production interface changes.

- [x] Save existing test inventory and source test bodies before the cut.
- [x] Convert all hand-maintained includes in the kernel test owner to modules, retaining test bodies/cfgs; separate common fixtures from scenario tests.
- [x] Commit mechanical relocation, then explicit imports and smallest useful fixture visibility, then formatting independently.
- [x] Compare full kernel test inventories and unchanged test bodies. Run the kernel owning test target and strict Clippy. Expected: no missing tests, no new warnings, no changed behavior.
- [x] Ratchet hygiene through the script and migrate source gates/selectors, never increase caps manually.

### Task 3: Shared security schema and domain declarations

**Files:** shared contract owners under `chio-core-types`, `chio-security-types`, `chio-runtime-core`, kernel/SQLite/control consumers; runtime and trust schema consumers; `spec/wire-schemas.lock`; domain gate debt.

**Interfaces:** Consumes current identifier bytes. Produces one declaration per consolidated value and direct consumer imports.

- [x] Inventory duplicated security declarations and all six duplicated byte domains; capture current bytes/canonical fixture evidence.
- [x] Consolidate all six byte-domain duplicates, native dispatch policy/replay/active response schema pairs, and runtime schema duplicates using existing dependency direction.
- [x] Add fixed canonical digest fixtures for moved domains and schema pins; run existing canonical/replay tests and affected dependency checks. Expected: byte identities unchanged and no cycles.
- [x] Refresh wire lock and domain debt via their scripts; run gates and strict Clippy for changed owners. Expected: duplicate counts shrink with no new exceptions.
- [x] Commit source, gate updates and evidence; reconcile remaining queue and propose the next substantive batch.

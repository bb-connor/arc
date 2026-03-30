---
phase: 8
slug: core-enforcement
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-22
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | Cargo.toml workspace |
| **Quick run command** | `cargo test --workspace --lib` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --workspace --lib`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 08-01-01 | 01 | 1 | SCHEMA-04 | unit | `cargo test -p arc-kernel budget_store` | ❌ W0 | ⬜ pending |
| 08-01-02 | 01 | 1 | SCHEMA-05 | unit | `cargo test -p arc-core capability` | ❌ W0 | ⬜ pending |
| 08-01-03 | 01 | 1 | SCHEMA-06 | unit | `cargo test -p arc-core receipt` | ❌ W0 | ⬜ pending |
| 08-02-01 | 02 | 1 | SEC-01 | unit | `cargo test -p arc-kernel checkpoint` | ❌ W0 | ⬜ pending |
| 08-02-02 | 02 | 1 | SEC-02 | unit | `cargo test -p arc-kernel checkpoint` | ❌ W0 | ⬜ pending |
| 08-03-01 | 03 | 1 | SEC-05 | unit | `cargo test -p arc-guards velocity` | ❌ W0 | ⬜ pending |
| 08-04-01 | 04 | 2 | SCHEMA-04,SEC-05 | integration | `cargo test -p arc-kernel integration` | ❌ W0 | ⬜ pending |
| 08-04-02 | 04 | 2 | SEC-01,SEC-02 | integration | `cargo test -p arc-kernel checkpoint_integration` | ❌ W0 | ⬜ pending |
| 08-04-03 | 04 | 2 | SCHEMA-06 | integration | `cargo test -p arc-kernel financial_receipt` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Budget store monetary tests in `crates/arc-kernel/src/budget_store.rs`
- [ ] Checkpoint unit tests in `crates/arc-kernel/src/checkpoint.rs`
- [ ] Velocity guard tests in `crates/arc-guards/src/velocity.rs`
- [ ] FinancialReceiptMetadata serde tests in `crates/arc-core/src/receipt.rs`

*Existing test infrastructure (cargo test) covers all framework needs.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| HA overrun bound documentation | Phase 8 SC-5 | Documentation review | Verify SAFETY comment in try_charge_cost documents overrun = max_cost_per_invocation x node_count |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

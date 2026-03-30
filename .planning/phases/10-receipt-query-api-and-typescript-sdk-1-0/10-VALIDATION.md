---
phase: 10
slug: receipt-query-api-and-typescript-sdk-1-0
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-22
---

# Phase 10 -- Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust), vitest (TypeScript) |
| **Config file** | Cargo.toml, packages/sdk/arc-ts/package.json |
| **Quick run command** | `cargo test --workspace --lib` |
| **Full suite command** | `cargo test --workspace && cd packages/sdk/arc-ts && npx vitest run` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --workspace --lib`
- **After every plan wave:** Run full suite
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 10-01-01 | 01 | 1 | PROD-01 | unit | `cargo test -p arc-kernel receipt_query` | ❌ W0 | ⬜ pending |
| 10-02-01 | 02 | 2 | PROD-01 | integration | `cargo test -p arc-cli receipt_list` | ❌ W0 | ⬜ pending |
| 10-03-01 | 03 | 2 | PROD-06 | unit | `cd packages/sdk/arc-ts && npx vitest run` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Receipt query tests in `crates/arc-kernel/src/receipt_store.rs` or receipt_query module
- [ ] TypeScript SDK DPoP and query client tests

*Existing test infrastructure covers framework needs.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| npm publish pipeline | PROD-06 | Requires npm registry access | Dry-run npm publish --dry-run and verify package contents |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

---
phase: 9
slug: compliance-and-dpop
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-22
---

# Phase 9 -- Validation Strategy

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
| 09-01-01 | 01 | 1 | COMP-03, COMP-04 | unit | `cargo test -p pact-kernel retention` | ❌ W0 | ⬜ pending |
| 09-02-01 | 02 | 1 | SEC-03, SEC-04 | unit | `cargo test -p pact-kernel dpop` | ❌ W0 | ⬜ pending |
| 09-03-01 | 03 | 2 | COMP-01 | integration | `cargo test --workspace` | ✅ | ⬜ pending |
| 09-04-01 | 04 | 2 | COMP-02 | integration | `cargo test --workspace` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Retention policy tests in `crates/pact-kernel/src/receipt_store.rs` or new retention module
- [ ] DPoP proof and nonce replay tests in `crates/pact-kernel/src/dpop.rs`

*Existing test infrastructure (cargo test) covers all framework needs.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Colorado compliance doc accuracy | COMP-01 | Legal/regulatory content review | Review docs/compliance/colorado-sb-24-205.md against statute text |
| EU AI Act compliance doc accuracy | COMP-02 | Legal/regulatory content review | Review docs/compliance/eu-ai-act-article-19.md against regulation text |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

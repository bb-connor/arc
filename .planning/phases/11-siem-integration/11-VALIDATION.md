---
phase: 11
slug: siem-integration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-23
---

# Phase 11 -- Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | Cargo.toml workspace |
| **Quick run command** | `cargo test -p arc-siem` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p arc-siem`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 11-01-01 | 01 | 1 | COMP-05 | unit | `cargo test -p arc-siem` | ❌ W0 | ⬜ pending |
| 11-02-01 | 02 | 2 | COMP-05 | unit | `cargo test -p arc-siem` | ❌ W0 | ⬜ pending |
| 11-03-01 | 03 | 3 | COMP-05 | integration | `cargo test -p arc-siem --test integration` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] arc-siem crate with Cargo.toml and src/lib.rs
- [ ] ExporterManager and DLQ unit tests
- [ ] Splunk HEC and ES bulk exporter unit tests with wiremock

*Existing test infrastructure (cargo test) covers all framework needs.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| arc-kernel has no HTTP client deps | COMP-05 SC-2 | Dep graph inspection | `cargo tree -p arc-kernel \| grep -i reqwest` returns empty |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

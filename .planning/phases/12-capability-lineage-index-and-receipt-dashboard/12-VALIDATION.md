---
phase: 12
slug: capability-lineage-index-and-receipt-dashboard
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-23
---

# Phase 12 -- Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust), vite build (TypeScript/React) |
| **Config file** | Cargo.toml, dashboard/package.json |
| **Quick run command** | `cargo test --workspace --lib` |
| **Full suite command** | `cargo test --workspace && cd dashboard && npm run build` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --workspace --lib`
- **After every plan wave:** Run full suite
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 12-01-01 | 01 | 1 | PROD-02 | unit | `cargo test -p arc-kernel capability_index` | ❌ W0 | ⬜ pending |
| 12-02-01 | 02 | 2 | PROD-03 | unit | `cargo test -p arc-kernel agent_query` | ❌ W0 | ⬜ pending |
| 12-03-01 | 03 | 2 | PROD-04 | build | `cd dashboard && npm run build` | ❌ W0 | ⬜ pending |
| 12-04-01 | 04 | 3 | PROD-05 | integration | `cargo test -p arc-cli dashboard` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Capability lineage tests in arc-kernel
- [ ] Dashboard SPA scaffolded with React 18 + Vite 6

*Existing test infrastructure covers Rust; npm handles frontend.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Non-engineer can use dashboard | PROD-05 | UX/usability judgment | Open dashboard in browser, filter by agent, inspect delegation chain |
| Dashboard visual quality | PROD-04 | Visual inspection | Screenshots of receipt list, detail panel, budget chart |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

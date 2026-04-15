---
phase: 393-ledger-and-narrative-reconciliation
milestone: v3.13
created: 2026-04-14
status: complete
requirements: [LEDGER-01, LEDGER-02, LEDGER-03, TRUTH-05, TRUTH-06]
---

# Phase 393 Context

## Why This Phase Exists

The architecture/runtime debate converged on two truths at once:

1. ARC has a real cross-protocol governance-kernel breakthrough in code.
2. The planning and narrative layer is still not truthful enough to support the
   strongest milestone or market-position claims.

That leaves a credibility problem:

- `v3.9`-`v3.11` were marked complete while their detailed ledgers still read
  as planned or partially unchecked.
- `STATE.md` metadata drifted badly enough to break roadmap tooling.
- older docs still overclaim formal verification and protocol maturity.
- some protocol docs still lag the shipped cross-protocol substrate and edge
  baseline.

## Phase Boundary

This phase is about truth and auditability, not new runtime features.

It must:

- reconcile the late-v3 milestone ledger to actual implementation truth
- repair stale planning metadata so tooling and humans see the same state
- narrow or update public-facing docs whose claims are stronger than the
  current repo can defend

It must not absorb the remaining runtime gaps. Those now live explicitly in:

- phase `394` for HTTP authority/evidence convergence
- phase `395` for A2A/ACP lifecycle and authority-surface closure
- phase `396` for post-closure claim qualification

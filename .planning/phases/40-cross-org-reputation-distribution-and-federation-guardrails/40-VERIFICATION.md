---
phase: 40
slug: cross-org-reputation-distribution-and-federation-guardrails
status: passed
completed: 2026-03-26
---

# Phase 40 Verification

Phase 40 passed targeted verification for conservative cross-org reputation
distribution in `v2.7`.

## Automated Verification

- `cargo test -p arc-reputation`
- `cargo test -p arc-cli --test local_reputation`
- `cargo test -p arc-cli --test evidence_export`

## Result

Passed. Phase 40 now satisfies `TRUST-04` and closes the documented
cross-org reputation portion of `TRUST-05`:

- imported reputation signals are evidence-backed, provenance-rich, and
  operator-visible
- imported trust stays separate from native local reputation truth instead of
  rewriting local receipt history
- local guardrails can reject proofless or stale remote trust before exposing
  an attenuated imported score
- docs and end-to-end regressions now describe and verify the conservative
  federation contract

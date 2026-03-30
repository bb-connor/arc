---
phase: 20
slug: ecosystem-conformance-and-operator-onboarding
status: passed
completed: 2026-03-25
---

# Phase 20 Verification

Phase 20 passed targeted verification for v2.2 operator onboarding, regression
coverage, and milestone closeout integrity.

## Automated Verification

- `cargo test -p arc-a2a-adapter --lib -- --nocapture`
- `cargo test -p arc-cli --test certify -- --nocapture`
- `cargo test -p arc-cli --test provider_admin -- --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`

## Result

Passed. Phase 20 now satisfies `ECO-01` and `ECO-02`:

- the new A2A auth, lifecycle, and certification-registry surfaces have direct
  regression coverage
- operator docs explain how to configure A2A partners and registry-backed
  certification flows without reading source code
- v2.2 planning artifacts now trace the completed milestone end to end

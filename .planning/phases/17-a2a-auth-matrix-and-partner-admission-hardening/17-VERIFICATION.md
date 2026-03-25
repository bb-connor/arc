---
phase: 17
slug: a2a-auth-matrix-and-partner-admission-hardening
status: passed
completed: 2026-03-25
---

# Phase 17 Verification

Phase 17 passed targeted verification for explicit A2A request-shaping auth
surfaces, fail-closed partner admission, and operator-visible auth diagnostics.

## Automated Verification

- `cargo test -p pact-a2a-adapter --lib -- --nocapture`

## Result

Passed. Phase 17 now satisfies `A2A-01` and `A2A-02`:

- operators can configure request headers, query params, and cookies explicitly
  through `A2aAdapterConfig`
- discovery and invoke stay fail closed when peer auth or partner-admission
  requirements cannot be satisfied
- denial paths now explain the partner, skill, interface, and tenant context
  that caused rejection

---
phase: 400-lifecycle-equivalent-protocol-mediation
status: passed
completed: 2026-04-14
---

# Phase 400 Verification

- `cargo test -p arc-a2a-edge -p arc-acp-edge`
- `git diff --check -- crates/arc-a2a-edge crates/arc-acp-edge docs/protocols/EDGE-CRATE-SYMMETRY.md spec/BRIDGES.md`

These checks verify truthful lifecycle rejection, deterministic discovery
handling, and the isolation of compatibility-only helpers from the default
authoritative surface.

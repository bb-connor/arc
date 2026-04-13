---
phase: 314-native-protocol-conformance-and-standards-track
created: 2026-04-13
status: complete
---

# Phase 314 Research

## Sources Reviewed

- `tests/conformance/README.md`
- `crates/arc-conformance/src/lib.rs`
- `crates/arc-conformance/src/load.rs`
- `crates/arc-conformance/src/model.rs`
- `crates/arc-conformance/src/report.rs`
- `crates/arc-conformance/src/runner.rs`
- `crates/arc-kernel/src/transport.rs`
- `crates/arc-core-types/src/message.rs`
- `docs/review/12-standards-positioning-remediation.md`

## Findings

1. The current conformance infrastructure already has the right building
   blocks: JSON scenario descriptors, machine-readable results, and generated
   Markdown reports.
2. Reusing the same crate but creating a dedicated native lane is lower-risk
   than stretching the MCP wave runner into a second protocol family.
3. The native ARC surface is partly artifact-oriented today:
   capability signatures, delegation attenuation, receipt integrity, and DPoP
   verification can be exercised as deterministic artifact checks, while the
   suite still needs executable `stdio` and `http` drivers for runtime-facing
   scenarios such as revocation propagation and governed transaction behavior.
4. The standards artifacts should be explicit about ARC's bounded positioning:
   map ARC concepts to adjacent standards and drafts, but do not claim those
   standards already define the whole ARC stack.

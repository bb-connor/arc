---
phase: 314
plan: 02
created: 2026-04-13
status: complete
---

# Summary 314-02

Phase `314` also makes the native suite discoverable and runnable.

- `tests/conformance/native/README.md` defines the native lane structure, the
  driver contracts, and the exact commands for running the suite against the
  checked-in fixture.
- `tests/conformance/README.md` now links the native lane alongside the
  existing MCP-focused conformance waves.
- The native runner writes machine-readable JSON results plus a generated
  Markdown report, matching the evidence style already used by the wider
  conformance crate.

This keeps the new lane aligned with the repo's existing evidence model rather
than introducing a one-off verification path.

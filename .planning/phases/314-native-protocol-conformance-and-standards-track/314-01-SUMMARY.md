---
phase: 314
plan: 01
created: 2026-04-13
status: complete
---

# Summary 314-01

Phase `314` adds a dedicated native ARC conformance lane instead of trying to
 overload the existing MCP Wave 1-5 harness.

- `tests/conformance/native/scenarios/` now contains JSON scenarios for the
  required categories: capability validation, delegation attenuation, receipt
  integrity, revocation propagation, DPoP verification, and governed
  transaction enforcement.
- `crates/arc-conformance/src/native_suite.rs` adds a native runner with three
  execution modes: `artifact`, `stdio`, and `http`.
- `crates/arc-conformance/src/bin/arc-native-conformance-runner.rs` exposes the
  suite as a CLI, and
  `crates/arc-conformance/src/bin/arc-native-conformance-fixture.rs` provides a
  deterministic fixture target for self-hosted verification.
- `crates/arc-conformance/tests/native_suite.rs` proves the suite runs end to
  end against the fixture and that the checked-in scenario set covers the
  required categories.

The resulting harness is language-neutral at the target boundary: third-party
implementations only need to satisfy the documented `stdio` or `http` driver
contracts, not link ARC Rust crates.

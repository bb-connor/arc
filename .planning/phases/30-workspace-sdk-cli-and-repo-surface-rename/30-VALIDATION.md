---
phase: 30
slug: workspace-sdk-cli-and-repo-surface-rename
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 30 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | workspace compile + CLI/help + package metadata grep |
| **Quick run command** | `cargo run -p arc-cli -- --help` |
| **Compatibility alias command** | `cargo run -p arc-cli --bin arc -- --help` |
| **Workspace compile command** | `cargo check --workspace` |
| **SDK identity command** | `rg -n "@arc-protocol/sdk|arc-py|github.com/.*/arc/" packages/sdk` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 30-01 | ARC-03 | `rg -n '^name = "arc-' crates/*/Cargo.toml` and `cargo check --workspace` |
| 30-02 | ARC-02, ARC-03 | `cargo run -p arc-cli -- --help`, `cargo run -p arc-cli --bin arc -- --help`, and `rg -n "@arc-protocol/sdk|arc-py|github.com/.*/arc/" packages/sdk` |
| 30-03 | ARC-01, ARC-08 | `cargo check --workspace`, `cargo run -p arc-cli -- --help`, and targeted script/reference updates in `README.md`, `tests/conformance/README.md`, and the release scripts |

## Coverage Notes

- this phase intentionally renames package identities before the deeper
  protocol/schema/doc sweep in Phase 31 and Phase 32
- physical repo paths such as `crates/arc-*` and `packages/sdk/arc-*` remain
  stable for now to avoid coupling the ARC identity shift to a filesystem move
- the `arc` CLI binary and legacy conformance bin names remain as compatibility
  aliases for one documented transition cycle

## Sign-Off

- [x] workspace packages resolve as `arc-*`
- [x] `arc` is the primary CLI surface and `arc` still works as a compatibility alias
- [x] SDK package identities are ARC-first
- [x] release/parity/conformance tooling follows the renamed package surface

**Approval:** completed

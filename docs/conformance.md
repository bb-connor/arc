# Standalone conformance flow

This document describes how an external implementer of the Chio (formerly
ARC) agent protocol runs the cross-language conformance suite without
checking out the Chio monorepo. The full flow is finalised in
M01.P4.T5; this stub lands in M01.P4.T1 alongside the publishable
`chio-conformance` crate so the README and Cargo metadata can link to a
real path.

> Status: stub. Expanded by M01.P4.T5 once the `chio conformance run` and
> `chio conformance fetch-peers` subcommands ship (M01.P4.T2 / M01.P4.T4).

## Overview

The conformance harness drives one or more peer implementations of the
Chio agent protocol against a curated set of scenario descriptors and
asserts that the peer's responses match the canonical fixtures shipped
with the harness. Scenarios cover:

- `mcp_core` - Model Context Protocol core flows
- `auth` - bearer and OAuth-local authentication paths
- `tasks` - long-running task lifecycle
- `nested_callbacks` - host-side callback fan-out
- `notifications` - server-initiated notifications
- `chio-extensions` - Chio-specific protocol extensions

Each scenario is a JSON descriptor under
`tests/conformance/scenarios/<category>/` plus a fixture tree that the
runner serves to the peer. A green run produces a Markdown
compatibility report alongside per-peer JSON result files.

## Standalone consumer flow

The intended external-consumer flow once M01.P4.T2 / T4 land is:

```bash
# 1. Install the harness and CLI from crates.io.
cargo install chio-conformance

# 2. Fetch sha256-pinned peer binaries for the languages you care about.
chio conformance fetch-peers

# 3. Run the harness, emit a JSON report.
chio conformance run --peer python --report json /tmp/report.json
```

Until those subcommands land, external consumers can drive the bundled
`chio-conformance-runner` binary directly:

```bash
cargo install chio-conformance
chio-conformance-runner \
    --peer python \
    --scenarios-dir <path/to/scenarios> \
    --results-dir <path/to/results> \
    --report-output <path/to/report.md>
```

The crate's `include` directive bundles the Python and Node.js reference
peers and the full scenario tree, so `cargo install chio-conformance`
downloads everything needed for the bundled peers in a single step.

## In-repo flow

When working inside the Chio repository, the default
`ConformanceRunOptions` resolve every path relative to the workspace
root via `chio_conformance::default_repo_root()`. The `in-repo-fixtures`
feature (on by default) preserves this behaviour; disable it via
`--no-default-features` when driving the runner with explicit absolute
paths.

## Related milestone work

- M01.P4.T1 (this ticket) - flip the crate to publishable shape.
- M01.P4.T2 - add `chio conformance run` subcommand to `chio-cli`.
- M01.P4.T3 - insta-snapshot integration test for the report shape.
- M01.P4.T4 - `chio conformance fetch-peers` plus `peers.lock.toml`.
- M01.P4.T5 - expand this document to the final consumer-facing form.
- M01.P4.T6 - C++ peer P0 (`mcp_core`, `auth`) coverage gate.

See `.planning/trajectory/01-spec-codegen-conformance.md` for the full
milestone scope.

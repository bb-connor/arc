# chio-cli Architecture

`chio-cli` owns the operator-facing `chio` binary. The crate is a thin product
shell over the core protocol, kernel, control plane, remote MCP, storage, guard,
passport, federation, replay, arena, and market crates. It should validate CLI
input, select local or remote backends, format operator output, and delegate
protocol behavior to the owning library crates.

## Boundaries

- `src/main.rs` wires the binary surface and keeps command modules reachable
  through the single `include!` entrypoint used by `src/bin/chio.rs`.
- `src/cli/types.rs` owns clap-visible command shapes, environment fallbacks,
  and help text.
- `src/cli/dispatch.rs` and `src/cli/dispatch/*` route parsed commands to
  command implementations without owning protocol semantics.
- `src/cli/runtime.rs`, `src/cli/session.rs`, `src/cli/mcp.rs`, and
  `src/cli/replay.rs` adapt operator input into calls against kernel, control
  plane, MCP, and replay library APIs.
- `src/doctor/*` owns local diagnostics. Probes report actionable operator
  health without mutating state unless `--fix` explicitly requests a safe
  repair.

## Invariants

- Secrets accepted by the CLI must prefer documented environment variables over
  argv forms and must not leak through help output.
- User-supplied identifiers and token mappings are validated before they cross
  into service configuration or durable stores.
- JSON output remains machine-readable and newline-terminated. Human output can
  be descriptive, but must not be the only path for automation.
- Shared protocol behavior belongs in the owning library crate. This crate can
  reject malformed CLI input, assemble requests, and render results.
- Tests should exercise command parsing, failure-closed validation, and
  operator-visible output contracts at the narrowest level that proves the
  product behavior.

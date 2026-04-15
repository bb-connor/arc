# Summary 318-01

Phase `318` started by making the CLI and kernel error path actionable instead
of string-only.

The implementation introduced:

- `arc_kernel::StructuredErrorReport` plus `KernelError::report()` in
  `crates/arc-kernel/src/kernel/mod.rs`
- `CliError::report()` in `crates/arc-control-plane/src/lib.rs`
- a new global `--format {human,json}` selector in
  `crates/arc-cli/src/cli/types.rs`, with `--json` preserved as a
  backward-compatible alias
- top-level CLI error rendering through `write_cli_error(...)` in
  `crates/arc-cli/src/cli/dispatch.rs`

Targeted verification that passed for this slice:

- `CARGO_TARGET_DIR=/tmp/arc-phase318-verify cargo check -p arc-kernel -p arc-control-plane -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase318-verify cargo test -p arc-kernel kernel_error_report --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase318-verify cargo test -p arc-control-plane cli_error_report --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase318-verify cargo test -p arc-cli --bin arc cli_entrypoint_tests`
- `git diff --check -- crates/arc-kernel/src/kernel/mod.rs crates/arc-kernel/src/lib.rs crates/arc-kernel/src/kernel/tests/all.rs crates/arc-control-plane/src/lib.rs crates/arc-cli/src/cli/types.rs crates/arc-cli/src/cli/dispatch.rs crates/arc-cli/src/main.rs`

This slice closes the developer-experience gap in the roadmap: both the
kernel and the CLI now expose stable error codes, structured context, and a
suggested fix, and the `arc` binary can emit those reports as machine-readable
JSON through the new `--format json` path.

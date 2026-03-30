status: passed

# Phase 30 Verification

## Result

Phase 30 passed. The workspace, CLI, SDK metadata, and active release tooling
now present ARC as the primary package and operator identity, while the
documented `arc` compatibility surfaces remain intact.

## Evidence

- `rg -n '^name = "arc-' crates/*/Cargo.toml`
- `cargo check --workspace`
- `cargo run -p arc-cli -- --help`
- `cargo run -p arc-cli --bin arc -- --help`
- `rg -n "@arc-protocol/sdk|arc-py|github.com/.*/arc/" packages/sdk`

## Notes

- the `arc` binary is primary, but `arc` still renders help and remains usable
  as the compatibility alias
- ARC package names now land cleanly in Cargo, npm, Python distribution
  metadata, and Go module metadata
- Phase 31 still has to handle the harder external-semantics layer: protocol
  markers, signed artifact families, schema IDs, config keys, and
  `did:arc`/`did:arc` migration rules

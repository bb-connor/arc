# Summary 125-01

Created ARC's first machine-readable extension-point inventory.

## Delivered

- added `crates/arc-core/src/extension.rs` with inventory types and validation
- published `docs/standards/ARC_EXTENSION_INVENTORY.json`
- enumerated the named kernel, store, provider, and bridge seams that later
  extension work must target

## Result

Later extension work now starts from one explicit inventory instead of
implicit trait discovery across the codebase.

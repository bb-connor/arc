---
phase: 306-dependency-hygiene-and-feature-gating
created: 2026-04-13
---

# Phase 306 Validation

## Required Evidence

- `serde_yaml` no longer appears in the workspace source or manifests.
- Direct workspace HTTP clients share `reqwest 0.13.2`.
- The normal `--no-default-features` workspace graph contains no alloy,
  ethers, or Solidity crates.
- The normal `--no-default-features` duplicate graph contains no duplicate
  headers for `reqwest`, `serde_yaml`, or `hashbrown`.

## Verification Commands

- `cargo check --no-default-features -p arc-link -p arc-anchor -p arc-settle -p arc-web3-bindings`
- `cargo check -p arc-kernel -p arc-policy -p arc-control-plane -p arc-cli`
- `cargo build --workspace --no-default-features`
- `cargo check --workspace`
- `cargo test -p arc-policy`
- `cargo test -p arc-link --no-default-features`
- `cargo test -p arc-cli runtime_hash_ignores_yaml_formatting_noise`
- `cargo test -p arc-cli yaml_tool_access_synthesizes_default_capabilities`
- `cargo tree -e normal -d --no-default-features`
- `cargo tree -e normal --no-default-features`

## Regression Focus

- YAML policy loading and serialization
- SQLite persistence paths touched by the `rusqlite` upgrade
- `arc-link` behavior with `web3` disabled
- Default web3-enabled workspace compilation

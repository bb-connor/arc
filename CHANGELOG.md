# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `chio-kernel` no longer enables `legacy-sync` by default. Downstream callers
  that still require the public `evaluate_tool_call_blocking` API must opt in
  with `--features legacy-sync` while migrating to `evaluate_tool_call`.
- Consolidated the workspace clippy lint policy (`unwrap_used`/`expect_used`
  denied) into a single canonical `[workspace.lints]` block that member crates
  inherit, rather than duplicating it per crate.

### Security

- Pinned every GitHub Actions workflow reference to an immutable commit SHA,
  closing the remaining floating `@v*`/`@stable` tags so CI cannot silently
  drift onto a new action release or compiler.
- Hardened the root container image: digest-pinned base images, a non-root
  runtime user, and OCI image labels, matching the sidecar and TEE images.

### Documentation

- Reconciled the `cargo-deny` configuration comments with the real waiver
  counts and rationale, removing stale or misleading caps.

## [0.1.0]

Initial public baseline of the Chio protocol kernel and its surrounding
toolchain. This release establishes the wire protocol, the policy and guard
runtime, the receipt and attestation pipeline, the federation and settlement
layers, and the multi-language SDK surface, together with the supply-chain,
fuzzing, and formal-verification apparatus that gate every change.

[Unreleased]: https://github.com/backbay-labs/chio/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/backbay-labs/chio/releases/tag/v0.1.0

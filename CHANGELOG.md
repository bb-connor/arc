# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

> **Superseded releases.** The `v0.1.0` GitHub release and the `0.1.0` npm and
> PyPI packages were published on 2026-04-22 from a source tree far behind
> `main`, and the `chio-*` 0.1.x crates on crates.io were built from the public
> mirror. They are deprecated and are not an upgrade or interoperability source.

The next release is a signed `0.2.0-alpha.N` preview built from `main`. No
preview has been tagged yet. Previews carry no format compatibility with each
other or with `v0.1.0`; see [Format Stability](docs/release/FORMAT_STABILITY.md).
Until the first preview is published, build from source
([install guide](docs/install/README.md)). The entries below summarize what is
on `main` for that preview.

### Added

- The agent process and security foundation (#1160): the durable process host,
  confined worker launch, and the security, store and kernel controls tracked
  in `docs/security/landing-ledger.md`. Its landing records qualification as
  incomplete and does not authorize a release.
- The MCP edge and `chio mcp serve-http` serve MCP revision `2026-07-28`
  stateless requests beside `2025-11-25`, and `initialize` answers with the
  served revision (#1278, #1319).
- Container launch records are signed and attribute the worker profile, and a
  receipt renders tool confinement only from a verified `FullyEnforced` launch
  record (#1265, #1292).
- Hosted MCP sessions persist subscriptions with re-authorization on restore,
  keep standard subscription authority live after activation, and journal a
  signed tombstone with its terminal fence (#1255, #1266, #1274).
- Swarm authority verifies bounded additive extensions (#1299).
- The cognition market: agents trade verified findings as signed,
  content-addressed artifacts, revealed through kernel-governed tool calls.
  Purchases settle under the kernel delivery contract (reversible hold,
  digest-checked reveal, capture only on matched delivery), backed by a
  challenge and slash lane with deterministic-replay evidence, signed status
  feeds with retraction propagation, quota-fenced redelivery, and pool
  purchasing. Ships as a qualified bounded single-operator profile on SQLite
  and a tenant-isolated hosted PostgreSQL profile behind an authenticated
  edge; cross-organization escrow remains conditional and unbuilt.

### Changed

- Chio-owned versioned formats collapse to a single v1 per family, and older
  versions, legacy paths and compatibility aliases are deleted (#1295, #1302,
  #1309, #1310, #1311, #1314, #1315, #1329). The rule is in
  [Format Stability](docs/release/FORMAT_STABILITY.md).
- The SDKs drop their dual paths, compatibility shims and fail-open knobs
  (#1268, #1271, #1272, #1313).
- Capability tokens require the schema member, and capability signatures are
  verified over one preimage (#1290, #1320).
- Release Qualification runs on dispatch from `main`, and internal path
  dependencies pin exact versions for packaging (#1258, #1291).
- `chio-kernel` provides both a synchronous `evaluate_tool_call_blocking`
  entrypoint and an asynchronous `evaluate_tool_call` entrypoint.
- Consolidated the workspace clippy lint policy (`unwrap_used`/`expect_used`
  denied) into a single canonical `[workspace.lints]` block that member crates
  inherit, rather than duplicating it per crate.

### Security

- The emergency admin token is compared in constant time, and x402 settlement
  fails closed (#1234).
- Receipt identity is signed at the producing boundary, and retained child
  receipt lookup is authenticated (#1242, #1256).
- The process cage resets ignored signals before exec and limits `ioctl` to
  reviewed requests (#1208).
- Narrowed the hosted market runtime database role to read-only on the
  derived spend accumulator, which only a security-definer trigger maintains.
  The role could otherwise forge a low total for its own tenant and pass the
  monthly ceiling that trigger enforces.
- Pinned every GitHub Actions workflow reference to an immutable commit SHA,
  closing the remaining floating `@v*`/`@stable` tags so CI cannot silently
  drift onto a new action release or compiler.
- Hardened the root container image: digest-pinned base images, a non-root
  runtime user, and OCI image labels, matching the sidecar and TEE images.

### Documentation

- ADR-0016 is accepted as the binding spend contract. Its predicate requires
  the execution nonce and the receipt to verify under the same kernel key, so
  authoritative spend receipts come from kernels on the classical signing
  floor; hybrid and PQ floors fail the predicate closed.
- `spec/PROTOCOL.md` is labeled 1.0 preview, not stable, and
  `spec/schemas/VERSION` stays at 1.0.0 (decision D20).
- Reconciled the `cargo-deny` configuration comments with the real waiver
  counts and rationale, removing stale or misleading caps.

[Unreleased]: https://github.com/backbay-labs/chio/commits/main

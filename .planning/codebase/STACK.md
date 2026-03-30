# Technology Stack

**Analysis Date:** 2026-03-19

## Languages

**Primary:**
- Rust 2021 / MSRV 1.93 - All runtime, CLI, adapter, policy, manifest, and test code

**Secondary:**
- Markdown - Research, roadmap, epic, and protocol documentation
- YAML / JSON - Policy inputs, manifests, fixtures, and wire payloads

## Runtime

**Environment:**
- Native Rust binaries via Cargo
- Async runtime driven by Tokio 1.x where HTTP, sessions, and transport handling need it

**Package Manager:**
- Cargo
- Lockfile: `Cargo.lock` present

## Frameworks

**Core:**
- Tokio 1.x - Async runtime for kernel/session/transport work
- Axum 0.8 - HTTP serving in `arc-cli` for the remote MCP and trust-control surfaces

**Testing:**
- Built-in Rust test runner (`cargo test`)
- GitHub Actions for format, clippy, build, and workspace test execution

**Build/Dev:**
- rustfmt - Formatting
- Clippy - Linting with warnings denied in CI

## Key Dependencies

**Critical:**
- `serde` / `serde_json` - Canonical wire types, config, manifests, and receipts
- `tokio` - Async execution and transport orchestration
- `axum` - Remote HTTP serving in the CLI
- `rusqlite` - Durable receipt, revocation, authority, and budget storage
- `ed25519-dalek` - Capability and receipt signing primitives
- `clap` - CLI command structure for `arc`

**Infrastructure:**
- `tracing` / `tracing-subscriber` - Logging and diagnostics
- `reqwest` / `ureq` - Remote control-plane and conformance HTTP interactions
- `thiserror` - Error types across crates

## Configuration

**Environment:**
- Most local workflows are CLI-flag driven rather than env-var driven
- Optional auth, DB, and seed inputs are passed as file paths or flags to `arc`

**Build:**
- `Cargo.toml` at the workspace root defines members, shared versions, and shared dependencies
- `.github/workflows/ci.yml` defines the main format/lint/build/test gate

## Platform Requirements

**Development:**
- Rust 1.93+
- Standard local process and filesystem access for wrapped-server and e2e tests
- Node and Python are optional but needed for live conformance waves

**Production:**
- Pre-release: the shipped surface is primarily a local or self-hosted Rust binary/HTTP deployment
- SQLite-backed trust state is the current durable storage baseline

---
*Stack analysis: 2026-03-19*
*Update after major dependency changes*

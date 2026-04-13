# Summary 273-01

Phase `273-01` established crate-owned hosted-MCP lifecycle coverage for
`arc-hosted-mcp`:

- [mod.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-hosted-mcp/tests/support/mod.rs) now starts the real `arc_hosted_mcp::serve_http` runtime in-process, generates wrapped mock-server and policy fixtures, serializes lifecycle env overrides during startup, and exposes reusable HTTP/SSE/admin helpers for hosted-session tests
- [session_lifecycle.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-hosted-mcp/tests/session_lifecycle.rs) now verifies session initialize, same-token reuse, TTL expiry, rejected reuse after expiry, and successful fresh re-initialize against the hosted runtime over real HTTP
- [273-01-PLAN.md](/Users/connor/Medica/backbay/standalone/arc/.planning/phases/273-arc-hosted-mcp-unit-tests/273-01-PLAN.md) and [273-02-PLAN.md](/Users/connor/Medica/backbay/standalone/arc/.planning/phases/273-arc-hosted-mcp-unit-tests/273-02-PLAN.md) were tightened so wave-1 verification is independently runnable and wave-2 isolation work requires receipt attribution rather than treating it as optional

Verification:

- `cargo test -p arc-hosted-mcp --test session_lifecycle -- --list`
- `cargo test -p arc-hosted-mcp --test session_lifecycle -- --nocapture`
- `cargo fmt --all -- --check`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/273-arc-hosted-mcp-unit-tests/273-01-PLAN.md`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/273-arc-hosted-mcp-unit-tests/273-02-PLAN.md`

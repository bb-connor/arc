# Summary 273-02

Phase `273-02` added crate-owned JWT session-isolation coverage for
`arc-hosted-mcp`:

- [session_isolation.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-hosted-mcp/tests/session_isolation.rs) now verifies that two tenant-distinct JWT sessions cannot reuse each other’s `MCP-Session-Id` and that the live runtime returns the existing authenticated-principal mismatch failure instead of crossing session boundaries
- [mod.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-hosted-mcp/tests/support/mod.rs) now supports JWT-backed hosted-runtime startup, explicit per-request bearer tokens, `tools/call` echo receipts, and admin receipt queries needed to assert isolation at the real HTTP boundary
- The same isolation target now proves trust and receipt attribution stay bound to the owning session by checking per-session tenant claims in admin trust output and matching admin tool-receipt `metadata.attribution.subject_key` values back to each session’s capability subject key

Verification:

- `cargo test -p arc-hosted-mcp hosted_mcp_rejects_cross_tenant_session_reuse -- --nocapture`
- `cargo test -p arc-hosted-mcp hosted_mcp_isolates_receipt_and_trust_attribution_by_session -- --nocapture`

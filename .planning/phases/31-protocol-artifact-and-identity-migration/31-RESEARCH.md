# Phase 31 Research

## Findings

1. Schema-family strings are concentrated but broad.
   `arc.*` identifiers still appear in `spec/PROTOCOL.md`, `arc-kernel`,
   `arc-credentials`, `arc-cli`, `arc-mcp-edge`, the SDKs, dashboard tests,
   and release/operator docs.

2. Not every `arc` marker should rename.
   Phase 29 explicitly froze `did:arc` and legacy `arc.*` artifact
   verification for historical data. Phase 31 therefore needs dual-stack or
   alias semantics, not a destructive replacement.

3. Environment/config names are still ARC-first.
   Runtime env vars such as `ARC_MCP_SESSION_*`, fixture knobs like
   `ARC_TEST_FILESYSTEM_RESOURCES`, and release/operator docs still expose
   ARC-first config naming.

4. Spec drift is guaranteed unless Phase 31 updates both code and contract docs.
   `spec/PROTOCOL.md`, standards profiles, guides, and release docs still
   describe ARC artifact/schema naming as primary. That must be reconciled with
   the ARC package/CLI surface before Phase 32 can credibly run qualification.

## Recommended Execution Shape

- Plan 31-01: introduce ARC-primary schema/marker constants while preserving
  legacy `arc.*` acceptance
- Plan 31-02: add ARC-first env/config aliases and artifact import/verification
  compatibility paths
- Plan 31-03: close the portable-trust/spec contract around `did:arc`,
  planned `did:arc`, and ARC-vs-ARC artifact issuance semantics

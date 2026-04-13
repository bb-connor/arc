# Phase 276 Context

## Goal

Add cross-crate integration coverage for the real ARC seams that exist today so
receipt, evidence, and fail-closed boundary regressions are caught before CI.

## Code Surface

- `crates/arc-hosted-mcp` hosts the runtime HTTP MCP surface and writes tool
  receipts via the ARC control-plane / kernel stack into a SQLite receipt store
- `crates/arc-siem` reads that receipt store directly with `ExporterManager` and
  fans events out to exporters
- `crates/arc-wall` is a separate companion-product CLI that writes its own
  bounded denied-access receipt/checkpoint package on top of the same ARC
  receipt and evidence-export substrate

## Important Constraint

The roadmap wording for phase 276 describes one direct
`hosted-mcp -> kernel -> wall -> siem` workflow chain. The repo does not
expose that runtime topology today:

- `arc-hosted-mcp` and `arc-siem` do share a real runtime seam through the
  kernel receipt SQLite database
- `arc-wall` is explicitly documented as a separate bounded companion product on
  the same ARC substrate, not a policy stage inside hosted-mcp's request path
- `arc-wall` currently generates its own denied receipt and ARC evidence package
  rather than consuming hosted-mcp receipts directly

Phase 276 should therefore test the real cross-crate seams that exist:

1. hosted-mcp/kernel receipts are exportable by arc-siem from the exact same
   receipt database
2. fail-closed hosted-mcp errors do not emit partial receipts, so arc-siem sees
   nothing to export
3. arc-wall's bounded denied receipt path stays compatible with the shared ARC
   receipt/evidence substrate and can also flow through arc-siem

## Requirement Mapping

- `TEST-12`: prove real shared-substrate integration across crates
  hosted-mcp/kernel -> siem on the live receipt DB, plus arc-wall companion
  receipt compatibility with siem on the same ARC receipt substrate
- `TEST-13`: prove fail-closed behavior across the real seams that exist
  hosted-mcp auth / request errors emit no partial receipts, and arc-wall keeps
  its bounded denied-control path explicit rather than silently widening scope

## Execution Direction

- Extend hosted-mcp test support to expose the temp receipt DB path for
  end-to-end manager/export verification
- Add a hosted-mcp integration test that issues a real tool call, then exports
  the resulting receipt through arc-siem
- Add a hosted-mcp fail-closed integration test that triggers an upstream auth
  error and proves no receipt or SIEM export occurs
- Factor a testable arc-wall receipt-store helper so the bounded denied receipt
  path can be exported through arc-siem without changing shipped CLI behavior

## Files Likely In Scope

- `crates/arc-hosted-mcp/Cargo.toml`
- `crates/arc-hosted-mcp/tests/support/mod.rs`
- `crates/arc-hosted-mcp/tests/cross_crate_pipeline.rs`
- `crates/arc-wall/Cargo.toml`
- `crates/arc-wall/src/commands.rs`
- `docs/arc-wall/README.md`
- `docs/arc-wall/CONTROL_PATH.md`

---
phase: 308-sdk-publication
created: 2026-04-13
status: complete
---

# Phase 308 Research

## Findings

- `packages/sdk/arc-ts` was already named `@arc-protocol/sdk` at version
  `1.0.0`, exported `ArcClient`, `ArcSession`, and `ReceiptQueryClient`, and
  already had a pack-and-install release script.
- `packages/sdk/arc-py` still declared `name = "arc-py"` and
  `__version__ = "0.1.0"`, and its release scripts only verified `ArcClient`
  and `ArcSession`.
- `arc mcp serve-http` sessions already expose the active capability set on
  `GET /admin/sessions/{session_id}/trust`, which gives the examples a stable
  capability id to feed into receipt queries without inventing a new SDK-only
  control-plane contract.
- `examples/docker/mock_mcp_server.py` and `examples/docker/policy.yaml`
  already provide a minimal governed HTTP demo topology that phase `308` can
  reuse directly.

## Consequences

- The TypeScript work can stay focused on documentation, example coverage, and
  version consistency instead of API expansion.
- The Python SDK needs both the publication rename and the missing receipt
  query surface to reach parity with the phase contract.
- The official SDK examples should assume a running ARC deployment but the repo
  also needs one deterministic verification script that boots that deployment
  locally and runs both examples end to end.

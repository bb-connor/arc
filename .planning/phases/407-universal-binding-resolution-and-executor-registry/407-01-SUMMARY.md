# Phase 407 Summary

Phase 407 replaced edge-local authoritative target branching with a shared
registry-backed path.

## Delivered

- `arc-cross-protocol` now exposes `TargetProtocolRegistry` and
  `target_protocol_for_tool_with_registry`.
- `CrossProtocolOrchestrator` now executes via a registry rather than edge-local
  `Native|Mcp` branch tables.
- Added `OpenAiTargetExecutor` as a qualified additional target family.
- A2A and ACP now resolve published/runtime authoritative bindings through the
  shared registry and fail closed when a target family is not registered.
- Added edge-level regression coverage for `open_ai` target bindings.

## Outcome

`FABRIC3-01` and `FABRIC3-02` are satisfied locally.

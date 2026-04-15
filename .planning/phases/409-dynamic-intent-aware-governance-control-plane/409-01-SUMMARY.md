# Phase 409 Summary

Phase 409 turned route choice into a real control-plane decision instead of a
static bridge hint.

## What Shipped

- shared route-planning types now model candidate availability, select,
  attenuate, and deny outcomes
- `CrossProtocolOrchestrator` now plans authoritative routes from governed
  intent, policy, capability, and runtime availability
- signed route-selection evidence is now emitted on the authoritative HTTP,
  MCP, OpenAI, A2A, and ACP paths
- deny and attenuation outcomes are now receipt-bearing and explicit rather
  than implicit fallbacks

## Requirements Closed

- `CTRL3-01`
- `CTRL3-02`
- `CTRL3-03`

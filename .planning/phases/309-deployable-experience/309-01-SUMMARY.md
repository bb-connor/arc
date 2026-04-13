---
phase: 309
plan: 01
created: 2026-04-13
status: complete
---

# Summary 309-01

Phase 309 turned the old single-container Docker example into a real local ARC
deployment path. The repo `Dockerfile` now produces two demo targets from the
same source tree: `arc-trust-demo`, which serves `arc trust serve` plus the
receipt dashboard, and `arc-mcp-demo`, which runs `arc mcp serve-http` in
front of the wrapped demo MCP subprocess.

The example compose topology in `examples/docker/compose.yaml` now wires those
services together with explicit `ARC_CONTROL_URL`, service-token sharing, a
named state volume, and a trust-service health check. To keep the onboarding
path within the roadmap budget, the demo image now uses the debug-profile
`arc` binary instead of a full release build; the timed Docker smoke completed
in `170.04s` on this machine.

The example docs were updated so `examples/docker` is now a true quickstart
entry point: `docker compose up -d`, run the smoke client, then open the
viewer URL and inspect the governed receipt.

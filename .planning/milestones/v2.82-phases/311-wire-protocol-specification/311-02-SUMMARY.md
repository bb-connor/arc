---
phase: 311
plan: 02
created: 2026-04-13
status: complete
---

# Summary 311-02

The wire spec now carries the lifecycle diagrams that were missing from the
broader repository profile.

- Hosted initialization is documented as the real `POST /mcp initialize`
  plus SSE admission flow with `MCP-Session-Id`, `notifications/initialized`,
  and GET-based notification streaming.
- Capability issuance and delegated issuance are documented against the actual
  trust-control endpoints:
  `/v1/capabilities/issue` and `/v1/federation/capabilities/issue`.
- Revocation now shows the full shipped path from
  `POST /v1/revocations` into either proactive `capability_revoked`
  notification or a later terminal `tool_call_response` with
  `capability_revoked`.

This closes the main clarity gap from the old profile doc: an external
engineer can now see where initialization happens, where issuance happens, and
where the native message lane begins and ends.

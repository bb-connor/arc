---
phase: 381-claim-gate-qualification
status: passed
completed: 2026-04-14
---

# Phase 381 Verification

## Integration Proof Already Landed

- `cargo test -p arc-acp-proxy`
- `cargo test -p arc-a2a-edge`
- `cargo test -p arc-acp-edge`

These suites cover live-path ACP cryptographic enforcement plus A2A/ACP
kernel-mediated outward-edge receipt behavior, including allow/deny and
receipt-emission paths. The ACP proxy suite also covers invalid-token cases.

## Operator Verification

- `cargo test -p arc-api-protect`
- `cargo test -p arc-tower`
- `go test ./...` in `sdks/k8s/controller`

These commands prove the corrective-runtime slice that the claim gate depends
on: durable sidecar receipt persistence, bound/raw request-body handling in
`arc-tower`, and fail-closed Kubernetes token/scope enforcement.

## Defensible Claim

ARC can now defend this narrower claim:

- ARC is a signed governance kernel and substrate for HTTP APIs plus the
  shipped MCP, A2A, ACP, and OpenAI execution lanes.

ARC still cannot honestly claim:

- a fully realized universal cross-protocol orchestrator
- fully shipped dynamic governance
- the strongest market-position language as demonstrated runtime fact

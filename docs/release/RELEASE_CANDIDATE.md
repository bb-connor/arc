# Release Candidate Surface

This document defines the supported `v1` release-candidate surface for this repository.

It is intentionally narrower than the broader protocol draft in [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md).

## Supported Guarantees

- Capability-scoped tool access is mediated by the kernel rather than delegated directly to the agent.
- Allow, deny, cancelled, and incomplete tool outcomes produce signed receipts.
- Filesystem-shaped tool access and filesystem-backed resource reads fail closed outside negotiated roots.
- Remote hosted sessions expose one documented lifecycle contract covering `ready`, `draining`, `deleted`, `expired`, and `closed`.
- Remote HTTP supports POST request handling plus standalone GET `/mcp` SSE with bounded retained-notification replay.
- Direct, wrapped, and remote paths share one ownership model for tasks, cancellation, and late async notifications.
- The wrapped MCP compatibility surface now covers tools, resources, prompts, completions, nested flows, auth discovery, notifications, and the task slice exercised by the live JS and Python peers.
- HushSpec is the canonical policy authoring path for new work; legacy PACT YAML remains a supported compatibility input.

## Supported Defaults And Limits

These values are the current documented defaults or intentional bounds that operators can rely on unless they configure a stricter value.

| Limit or default | Value | Source |
| --- | --- | --- |
| default max capability TTL | `3600s` | `crates/pact-cli/src/policy.rs` |
| default delegation depth | `5` | `crates/pact-cli/src/policy.rs` |
| default streamed tool duration limit | `300s` | `crates/pact-kernel/src/lib.rs` |
| default streamed tool total-byte limit | `256 MiB` | `crates/pact-kernel/src/lib.rs` |
| default MCP page size | `50` | `crates/pact-mcp-adapter/src/edge.rs` |
| background-task progression per edge tick | `8 tasks` | `crates/pact-mcp-adapter/src/edge.rs`, `crates/pact-mcp-adapter/src/transport.rs` |
| remote session idle expiry | `15 min` | `crates/pact-cli/src/remote_mcp.rs` |
| remote session drain grace | `5 s` | `crates/pact-cli/src/remote_mcp.rs` |
| remote session tombstone retention | `30 min` | `crates/pact-cli/src/remote_mcp.rs` |

Release qualification depends on those defaults being covered by tests and on stricter user-provided values continuing to fail closed.

## Explicit Non-Goals

The scoped `v1` release candidate does not claim:

- multi-region consensus or Byzantine trust replication
- a full OS sandbox manager
- complete theorem-prover coverage for the draft protocol
- production networking, mTLS, and federation breadth described by the draft protocol
- a performance-first rewrite or large-scale throughput tuning program

## Migration Story

- Existing wrapped MCP servers can be hosted through `pact mcp serve` and `pact mcp serve-http`.
- New policy work should start from `examples/policies/canonical-hushspec.yaml`.
- Existing deployments may keep using legacy PACT YAML as a compatibility input.
- Native adoption starts from [`docs/NATIVE_ADOPTION_GUIDE.md`](../NATIVE_ADOPTION_GUIDE.md) and [`examples/hello-tool`](../../examples/hello-tool).

## Extension Policy

- Keep MCP compatibility claims tied to the behavior exercised by the checked-in conformance scenarios and live peer runs.
- Keep PACT-native extensions explicit rather than implying they are part of baseline MCP compatibility.
- Add new release claims only when they are backed by a proving artifact in [QUALIFICATION.md](QUALIFICATION.md).
- Do not move unresolved architectural work into the release candidate by renaming it as hardening.

## Operator Guidance

- Use `./scripts/ci-workspace.sh` for ordinary local validation.
- Use `./scripts/qualify-release.sh` before treating a branch as release-candidate material.
- Use [`docs/release/RELEASE_AUDIT.md`](RELEASE_AUDIT.md) as the go/no-go record instead of relying on tribal knowledge.
